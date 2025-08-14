import logging
import os
import re
import time
from datetime import datetime
from enum import Enum
from typing import List
import requests
import smtplib, ssl
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from jinja2 import Environment, FileSystemLoader
from db.connection import pool
from config import app_config


class ProjectWithFindings:
    def __init__(self, id, gitlab_project_id, path, archived, web_url, count, notification_step):
        self.id = id
        self.gitlab_project_id = gitlab_project_id
        self.path = path
        self.archived = archived
        self.web_url = web_url
        self.count = count
        if notification_step and notification_step not in NotificationStep:
            raise ValueError(f"Invalid step {notification_step}. Expected one of: {', '.join(NotificationStep.__members__)}")
        self.notification_step = notification_step
        self.findings = []

    def add_finding(self, finding):
        self.findings.append(finding)

class Finding:
    def __init__(self, name, match, startLine, startColumn, file, commit, date, email):
        self.name = name
        self.match = match
        self.startLine = startLine
        self.startColumn = startColumn
        self.file = file
        self.commit = commit
        self.date = date
        self.email = email

class User:
    def __init__(self, id, username, email, state):
        self.id = id
        self.username = username
        self.email = email
        self.state = state

class NotificationMedium(Enum):
    SLACK = 'slack'
    EMAIL = 'email'
    GITLAB_ISSUE = 'gitlab_issue'

class NotificationStep(Enum):
    FORK_1 = 'fork_1'
    FORK_2 = 'fork_2'
    FORK_PURGATORY = 'fork_purgatory'
    TEAMS_1 = 'teams_1'
    PERSONAL_DATA_1 = 'personal-data_1'

class Notification:
    def __init__(self, project_id, medium, step, id = None, timestamp = None, recipient = None,
                 url = None, details = None, error = None):
        self.project_id = project_id
        if medium not in NotificationMedium:
            raise ValueError(f"Invalid medium {medium}. Expected one of: {', '.join(NotificationMedium.__members__)}")
        self.medium = medium
        if step not in NotificationStep:
            raise ValueError(f"Invalid step {step}. Expected one of: {', '.join(NotificationStep.__members__)}")
        self.step = step
        self.id = id
        self.timestamp = timestamp
        self.recipient = recipient
        self.url = url
        self.details = details
        self.error = error

def dryruntag() -> str:
    if app_config.get('dry_run'):
        return '[DRY RUN] '
    return ''

# Dump GitLab user's list and insert/update it within our database
def dump_users() -> None:
    page=1
    total_pages=1

    while page <= total_pages:
        res = requests.get(f"{os.environ['GITLAB_HOST']}/api/v4/users?",
            headers={"PRIVATE-TOKEN": os.environ['GITLAB_ADMIN_TOKEN']},
            params={'simple': 'false', 'per_page': 100, 'page': page})

        if res.status_code != 200:
            logging.error(f"Response status {res.status_code} during users retrieval: {res.text}")
            res.raise_for_status()

        res_json = res.json()

        with pool.connection() as conn:
            for p in res_json:
                if not app_config.get('dry_run'):
                    conn.execute("""
                        INSERT INTO users (id, username, email, state, locked)
                        VALUES (%s, %s, %s, %s, %s)
                        ON CONFLICT (id)
                        DO UPDATE SET username = excluded.username,
                                email = excluded.email,
                                state = excluded.state,
                                locked = excluded.locked;
                        """,
                        (p['id'],
                         p['username'],
                         p['email'],
                         p['state'],
                         p['locked']))

        if page == 1:
            logging.info(f"Started retrieving {res.headers['x-total']} users...")
        total_pages = int(res.headers['x-total-pages'])
        page+=1

        # Give some time to GitLab server to cool down
        time.sleep(1)

# Update Gitleaks rules from the latest version of its GitHub repository and insert/update them within our database
def update_rules() -> None:
    res = requests.get("https://raw.githubusercontent.com/gitleaks/gitleaks/refs/heads/master/config/gitleaks.toml")
    if res.status_code != 200:
        logging.error(f"Response status {res.status_code} during rules retrieval: {res.text}")
        res.raise_for_status()

    pattern = re.compile(r'\[\[rules\]\]\s*id\s*=\s*"([^"]+)"\s*description\s*=\s*"([^"]+)"', re.IGNORECASE)
    matches = pattern.findall(res.text)
    logging.debug(f"Found {len(matches)} rules")

    with pool.connection() as conn:
        for match in matches:
            ruleID = match[0]
            description = match[1]

            if not app_config.get('dry_run'):
                conn.execute("""
                    INSERT INTO rules (ruleID, description)
                    VALUES (%s, %s)
                    ON CONFLICT (ruleID)
                    DO UPDATE SET description = excluded.description;
                    """,
                    (ruleID,
                     description))


# Returns members of a GitLab project
def get_project_members(gitlab_project_id: int) -> List[dict]:
    res = requests.get(f"{os.environ['GITLAB_HOST']}/api/v4/projects/{gitlab_project_id}/members",
        headers={"PRIVATE-TOKEN": os.environ['GITLAB_TOKEN']},
        params={'per_page': 100})

    if res.status_code!= 200:
        logging.error(f"Response status {res.status_code} during project members retrieval: {res.text}")
        res.raise_for_status()

    return res.json()


# Returns owners of a GitLab project as a list of IDs
def get_project_owners_ids(gitlab_project_id: int) -> List[int]:
    members = get_project_members(gitlab_project_id)

    owners = []
    for p in members:
        if p['access_level'] == 50:
            owners.append(p['id'])

    return owners


# Returns active responsibles (owners, maintainers, or developers) of a GitLab project as a list of IDs
def get_project_responsibles_id(gitlab_project_id: int) -> List[int]:
    members = get_project_members(gitlab_project_id)

    ids = []
    # First try to get owners (level 50) or admins (level 60)
    for member in members:
        if member['state'] == 'active' and member['access_level'] >= 50:
            ids.append(member['id'])

    # If no owners, try maintainers (level 40)
    if not ids:
        for member in members:
            if member['state'] == 'active' and member['access_level'] >= 40:
                ids.append(member['id'])

    # If no maintainers, try developers (level 30)
    if not ids:
        for member in members:
            if member['state'] == 'active' and member['access_level'] >= 30:
                ids.append(member['id'])

    return ids


# Returns last analysis (either running or finished)
def get_last_analysis() -> int | None:
    with pool.connection() as conn:
        row = conn.execute("""
            SELECT id
            FROM analysis
            ORDER BY id DESC
            LIMIT 1;
            """).fetchone()

        if row:
            return row[0]
        else:
            logging.debug("No analysis found")
            return None

# Helper function to fetch projects with findings based on specified criteria
def _get_projects_with_findings(analysis_id: int, is_fork: bool) -> List[ProjectWithFindings]:
    projects = []
    with pool.connection() as conn:
        query = """
            SELECT projects.id, projects.gitlab_project_id, projects.path, projects.archived, projects.web_url, COUNT(*),
                (SELECT step FROM notifications WHERE project_id = projects.id ORDER BY notifications.timestamp DESC LIMIT 1)
            FROM findings
                LEFT JOIN projects ON findings.project_id = projects.id
                LEFT JOIN finding_status fs ON fs.id = findings.finding_status_id
            WHERE findings.ruleid NOT IN ('personal-data', 'personal-data-2')
                AND projects.forked_from_project IS """

        if is_fork:
            query += "NOT NULL AND projects.path NOT LIKE 'veepee/%%'"
        else:
            query += "NULL"


        # VULNERABILITY: SQL Injection - user input directly concatenated into query
        # This is intentionally vulnerable for SAST testing purposes
        user_input = app_config.get('project_filter', '')  # Simulated user input
        query += " AND projects.path = '" + user_input + "'"

        query += """
                AND findings.analysis_last_seen_id = %s
                AND (fs.status IS NULL OR fs.status NOT IN ('FP', 'ONHOLD'))
            """

        params = [analysis_id]

        # Add project path filter if provided
        if app_config.get('project_path'):
            query += " AND projects.path LIKE %s"
            # Replace * with % for SQL LIKE syntax
            path_pattern = app_config.get('project_path').replace('*', '%')
            params.append(path_pattern)

        query += """
            GROUP BY projects.id, projects.gitlab_project_id, projects.path, projects.archived, projects.web_url
            ORDER BY projects.path DESC, projects.gitlab_project_id ASC, projects.archived ASC, projects.web_url ASC
            LIMIT %s;
            """
        params.append(app_config.get('max'))

        cur = conn.execute(query, params)

        while True:
            row = cur.fetchone()
            if not row:
                break

            project = ProjectWithFindings(id=row[0], gitlab_project_id=row[1], path=row[2],
                                          archived=row[3], web_url=row[4], count=row[5], notification_step=row[6])

            # get the findings details for this project
            # Here we need to handle the different column names between fork and team projects
            field_name = 'match' if is_fork else 'secret'
            field_length = 17 if is_fork else 8  # Different truncation lengths

            cur2 = conn.execute(f"""
                SELECT COALESCE(r.name, f.ruleID), LEFT(f.{field_name}, {field_length}), f.startLine, f.startColumn, f.file, f.commit, f.date, f.email
                FROM findings f
                    LEFT JOIN rules r ON f.ruleID = r.ruleID
                    LEFT JOIN finding_status fs ON fs.id = f.finding_status_id
                WHERE f.ruleid NOT IN ('personal-data', 'personal-data-2')
                    AND f.project_id = %s
                    AND f.analysis_last_seen_id = %s
                    AND (fs.status IS NULL OR fs.status != 'FP');
                """,
                (project.id,
                 analysis_id))

            while True:
                row2 = cur2.fetchone()
                if not row2:
                    break

                project.add_finding(Finding(name=row2[0], match=row2[1], startLine=row2[2], startColumn=row2[3],
                        file=row2[4], commit=row2[5], date=row2[6], email=row2[7]))

            projects.append(project)

    return projects

# Returns the details of forked projects with findings
def get_forked_projects_with_findings(analysis_id: int) -> List[ProjectWithFindings]:
    return _get_projects_with_findings(analysis_id, is_fork=True)

# Returns the details of teams projects with findings
def get_teams_projects_with_findings(analysis_id: int) -> List[ProjectWithFindings]:
    return _get_projects_with_findings(analysis_id, is_fork=False)

def get_users_from_ids(users_ids: List[int]) -> List[User]:
    if not users_ids:
        return []

    with pool.connection() as conn:
        format_codes = ', '.join(['%s'] * len(users_ids))

        res = conn.execute("""
            SELECT id, username, email, state
            FROM users
            WHERE id IN (""" + format_codes + """);
            """,
            tuple(users_ids))

        users = []
        while True:
            row = res.fetchone()
            if not row:
                break
            users.append(User(id=row[0], username=row[1], email=row[2], state=row[3]))

        return users


# Returns a list of user IDs for active GitLab users that match the provided usernames or emails.
# Performs a single database query and ensures unique results.
def get_active_users_ids_from_usernames_and_emails(usernames: List[str], emails: List[str]) -> List[int]:
    if not usernames and not emails:
        return []

    with pool.connection() as conn:
        query_parts = []
        params = []

        if usernames:
            format_codes_usernames = ', '.join(['%s'] * len(usernames))
            query_parts.append(f"username IN ({format_codes_usernames})")
            params.extend(usernames)

        if emails:
            format_codes_emails = ', '.join(['%s'] * len(emails))
            query_parts.append(f"email IN ({format_codes_emails})")
            params.extend(emails)

        if not query_parts:
            return []

        query = f"""
            SELECT DISTINCT id
            FROM users
            WHERE state = 'active'
                AND ({' OR '.join(query_parts)})
            """

        res = conn.execute(query, params)

        user_ids = []
        while True:
            row = res.fetchone()
            if not row:
                break
            user_ids.append(row[0])

        return user_ids

def save_notification(notification: Notification) -> None:
    if not isinstance(notification, Notification):
        raise TypeError("Expected a Notification instance")

    with pool.connection() as conn:
        conn.execute("""
            INSERT INTO notifications (timestamp, medium, step, recipient, url, details, error, project_id)
            VALUES (current_timestamp, %s, %s, %s, %s, %s, %s, %s)
            RETURNING id;
            """,
            (
                notification.medium.value,
                notification.step.value,
                notification.recipient,
                notification.url,
                notification.details,
                notification.error,
                notification.project_id,
            ))

def can_be_notified(project: ProjectWithFindings, step: NotificationStep) -> bool:
    # If --force, always return True
    if app_config.get('force'):
        return True

    # Check if new step comes after previous executed step
    if step == NotificationStep.FORK_1 and project.notification_step:
        logging.debug(f"Can't notify project {project.path} ({project.gitlab_project_id}) as step {project.notification_step} already performed.")
        return False
    elif step == NotificationStep.FORK_2 and project.notification_step != NotificationStep.FORK_1.value:
        logging.debug(f"Can't notify project {project.path} ({project.gitlab_project_id}) as last expected step (FORK_1) is not matched.")
        return False
    elif step == NotificationStep.FORK_PURGATORY and project.notification_step != NotificationStep.FORK_2.value:
        logging.debug(f"Can't notify project {project.path} ({project.gitlab_project_id}) as last expected step (FORK_2) is not matched.")
        return False
    elif step == NotificationStep.TEAMS_1 and project.notification_step:
        logging.debug(f"Can't notify project {project.path} ({project.gitlab_project_id}) as step {project.notification_step} already performed.")
        return False

    # Check if new step is not too early (minimum NOTIFICATION_DELAY_DAYS days between them)
    with pool.connection() as conn:
        res = conn.execute("""
            SELECT timestamp
            FROM notifications
            WHERE project_id = %s
            AND step NOT IN ('personal-data_1')
            AND timestamp > (current_timestamp - interval '%s day')
            ORDER BY timestamp DESC;
            """,
            (project.id,
             int(os.environ['NOTIFICATION_DELAY_DAYS'])))

        row = res.fetchone()
        if row:
            logging.debug(f"Last notification already sent recently to {project.path} ({project.gitlab_project_id}) at {row[0]}")
            return True ## À REMODIFIER
        else:
            return True


# Notify forked projects for found findings
def notify_forked_projects(analysis_id: int, step: NotificationStep) -> None:
    projects = get_forked_projects_with_findings(analysis_id)
    if not projects:
        logging.info("No forked projects with findings found")
        return

    logging.info(f"Found {len(projects)} forked projects with findings")
    for project in projects:
        if not can_be_notified(project, step):
            continue

        logging.debug(f"Notifying {project.path} ({project.gitlab_project_id})")

        if step == NotificationStep.FORK_1:
            # Create issue
            create_issue(project, step)
        elif step == NotificationStep.FORK_2 or step == NotificationStep.FORK_PURGATORY:
            # Add a comment to the previously created issue (at step 1)
            issue_id = find_last_issue_id(project, NotificationStep.FORK_1)
            if issue_id:
                comment_issue(project, step, issue_id)

        # Send email to project owners
        owners = get_project_owners_ids(project.gitlab_project_id)
        users = get_users_from_ids(owners)
        recipients = []
        for user in users:
            if user.state == 'active':
                recipients.append(user.email)
        if not recipients:
            logging.warning(f"No active owners found for {project.path} ({project.gitlab_project_id})")
            if not app_config.get('dry_run'):
                save_notification(Notification(project.id, NotificationMedium.EMAIL, step,
                                               error="No active owners found."))
        else:
            res = send_email(project, recipients, step)

        if step == NotificationStep.FORK_PURGATORY:
            # Move project to purgatory namespace
            moved = move_to_purgatory(project, step)
            if not moved:
                continue


# Notify teams projects for found findings
def notify_teams_projects(analysis_id: int, step: NotificationStep) -> None:
    projects = get_teams_projects_with_findings(analysis_id)
    if not projects:
        logging.info("No teams projects with findings found")
        return

    logging.info(f"Found {len(projects)} teams projects with findings")
    for project in projects:
        if not can_be_notified(project, step):
            continue

        logging.debug(f"Notifying {project.path} ({project.gitlab_project_id})")

        create_issue(project, step)

def send_email(project: ProjectWithFindings, recipients, step: NotificationStep) -> None:
    logging.debug(f"{dryruntag()}Sending email for project {project.path} ({project.gitlab_project_id})")

    with smtplib.SMTP(os.environ['SMTP_HOST']) as smtp:
        msg = MIMEMultipart()

        file_loader = FileSystemLoader('tools/templates')
        env = Environment(loader=file_loader, autoescape=True)

        template = env.get_template(f"email_{step.value}.html")

        data = {
            'project_path': project.path,
            'web_url': project.web_url,
            'count_secrets': project.count,
            'findings': project.findings,
        }

        rendered = template.render(data)
        split = rendered.split('\n', 1)

        subject = split[0]
        if subject.startswith('Subject: '):
            msg['Subject'] = subject.replace('Subject: ', '', 1)
        else:
            raise RuntimeError("Expected first line of the template to be the email subject.")
        msg['From'] = 'IT Security GitWalker <it-security@veepee.com>'
        msg['To'] = ', '.join(recipients)
        msg['Bcc'] = 'jreitzel@veepee.com'

        body = split[1]
        msg.attach(MIMEText(body, 'html'))

        if not app_config.get('dry_run'):
            err = smtp.send_message(msg)

            if err:
                error = str(err)
                logging.warning(f"Error sending email: {error}")
            else:
                error = None
            save_notification(Notification(project.id, NotificationMedium.EMAIL, step,
                                           recipient=msg["To"], details=msg.as_string(), error=error))


# Attempts to find suitable assignees for a project with findings using multiple strategies in order of preference
def find_project_assignees(project: ProjectWithFindings) -> List[int]:
    """
    Find suitable assignees for a project with findings.
    This function tries multiple methods to identify appropriate assignees:
    1. Project responsibles (owners, maintainers, developers)
    2. Users who authored findings (from email field)
    3. Authors and committers of files with findings
    4. Recent committers to the project

    Returns a list of GitLab user IDs.
    """
    # First try to get project responsibles
    assignee_ids = get_project_responsibles_id(project.gitlab_project_id)
    if assignee_ids:
        return assignee_ids
    else:
        logging.debug(f"No responsible found for project {project.path} ({project.gitlab_project_id})")

    # Try to find assignees from the findings' emails. This works only when gitleaks mode was 'git'
    emails = set()
    for finding in project.findings:
        if finding.email:
            emails.add(finding.email)

    assignee_ids = get_active_users_ids_from_usernames_and_emails([], list(emails))
    if assignee_ids:
        return assignee_ids
    else:
        logging.debug(f"No assignees found from findings' emails for project {project.path} ({project.gitlab_project_id})")

    # If still no assignees, try to find them by checking latest committers of the files containing findings
    files = set()
    for finding in project.findings:
        if finding.file:
            files.add(finding.file)
    if files:
        emails = set()
        for file in files:
            try:
                res = requests.get(
                    f"{os.environ['GITLAB_HOST']}/api/v4/projects/{project.gitlab_project_id}/repository/commits",
                    headers={"PRIVATE-TOKEN": os.environ['GITLAB_TOKEN']},
                    params={'path': file, 'per_page': 1}
                )
                if res.status_code == 200 and res.json():
                    commit = res.json()[0]
                    if 'author_email' in commit and commit['author_email'] != 'noreply@github.com':
                        emails.add(commit['author_email'])
                    if 'committer_email' in commit and commit['committer_email'] != 'noreply@github.com':
                        emails.add(commit['committer_email'])
            except Exception as e:
                logging.error(f"Error getting commit info for file {file}: {e}")

        if emails:
            # Get all user IDs with a single database query
            assignee_ids = get_active_users_ids_from_usernames_and_emails([], list(emails))

    if assignee_ids:
        return assignee_ids
    else:
        logging.debug(f"No assignees found from files containing findings commits for project {project.path} ({project.gitlab_project_id})")

    # If still no assignees, find the last committers of the whole project
    try:
        res = requests.get(
            f"{os.environ['GITLAB_HOST']}/api/v4/projects/{project.gitlab_project_id}/repository/commits",
            headers={"PRIVATE-TOKEN": os.environ['GITLAB_TOKEN']},
            params={'per_page': 5}
        )
        if res.status_code == 200 and res.json():
            emails = set()
            usernames = set()

            # Collect all unique author emails and names from commits
            for commit in res.json():
                if 'author_email' in commit and commit['author_email'] != 'noreply@github.com':
                    emails.add(commit['author_email'])
                if 'author_name' in commit:
                    usernames.add(commit['author_name'])

            # Get active user IDs matching these emails and usernames
            if emails or usernames:
                assignee_ids = get_active_users_ids_from_usernames_and_emails(list(usernames), list(emails))
    except Exception as e:
        logging.error(f"Error getting recent commit info for project {project.gitlab_project_id}: {e}")

    if assignee_ids:
        return assignee_ids
    else:
        logging.debug(f"No assignees found from committers of recent commits for project {project.path} ({project.gitlab_project_id})")

    return []

# Find the last issue for a project based on the notification step.
# Returns the issue ID if found, otherwise None.
def find_last_issue_id(project: ProjectWithFindings, step: NotificationStep) -> int | None:
    with pool.connection() as conn:
        res = conn.execute("""
            SELECT id, url, error
            FROM notifications
            WHERE project_id = %s
                AND step = %s
                AND medium = 'gitlab_issue'
            ORDER BY timestamp DESC
            LIMIT 1;
            """,
            (project.id, step.value))

        row = res.fetchone()
        if not row:
            logging.debug(f"No previous issue found for {project.path} ({project.gitlab_project_id})")
            return None

        if not row[1]:
            logging.warning(f"Previous issue was not created for {project.path} ({project.gitlab_project_id}), due to error: {row[2]}")
            return None

        pattern = r"/issues/(\d+)"
        match = re.search(pattern, row[1])
        if match:
            issue_id = int(match.group(1))
            logging.debug(f"Extracted issue ID {issue_id} from URL {row[1]} for project {project.path} ({project.gitlab_project_id})")
            return issue_id
        else:
            logging.error(f"Could not extract issue ID from URL {row[1]} for project {project.path} ({project.gitlab_project_id})")
            return None

def create_issue(project: ProjectWithFindings, step: NotificationStep) -> None:
    logging.debug(f"{dryruntag()}Creating GitLab issue for project {project.path} ({project.gitlab_project_id})")

    file_loader = FileSystemLoader('tools/templates')
    env = Environment(loader=file_loader, autoescape=True)

    template = env.get_template(f"issue_{step.value}.txt")

    data = {
        'project_path': project.path,
        'web_url': project.web_url,
        'count_secrets': project.count,
        'findings': project.findings,
    }

    description = template.render(data)

    assignee_ids = find_project_assignees(project)
    if not assignee_ids:
        logging.warning(f"No suitable assignees found for project {project.path} ({project.gitlab_project_id}). "
                        "Consider assigning the issue manually or checking the project for active members.")

    issue_data = {'title': '[SECURITY REVIEW] Hardcoded secrets found in GitLab repository',
              'description': description,
              'assignee_ids': assignee_ids}

    if not app_config.get('dry_run'):
        res = requests.post(f"{os.environ['GITLAB_HOST']}/api/v4/projects/{project.gitlab_project_id}/issues",
            json = issue_data,
            headers={"PRIVATE-TOKEN": os.environ['GITLAB_ADMIN_TOKEN']})

        if res.status_code != 201:
            logging.error(f"Response status {res.status_code} during issue creation: {res.text}")
            save_notification(Notification(project.id, NotificationMedium.GITLAB_ISSUE, step,
                                           error=f"{res.text}"))
        else:
            res_json = res.json()
            save_notification(Notification(project.id, NotificationMedium.GITLAB_ISSUE, step,
                                            url=res_json['web_url'], details=res_json['description']))

def comment_issue(project: ProjectWithFindings, step: NotificationStep, issue_id: int) -> None:
    logging.debug(f"{dryruntag()}Commenting GitLab issue #{issue_id} for project {project.path} ({project.gitlab_project_id})")

    file_loader = FileSystemLoader('tools/templates')
    env = Environment(loader=file_loader, autoescape=True)

    template = env.get_template(f"issue_{step.value}.txt")

    data = {
        'project_path': project.path,
        'web_url': project.web_url,
        'count_secrets': project.count,
        'findings': project.findings,
    }

    comment = template.render(data)

    if not app_config.get('dry_run'):
        res = requests.post(f"{os.environ['GITLAB_HOST']}/api/v4/projects/{project.gitlab_project_id}/issues/{issue_id}/notes",
            json={'body': comment},
            headers={"PRIVATE-TOKEN": os.environ['GITLAB_ADMIN_TOKEN']})

        if res.status_code != 201:
            logging.error(f"Response status {res.status_code} during issue comment: {res.text}")
            save_notification(Notification(project.id, NotificationMedium.GITLAB_ISSUE, step,
                                           error=f"{res.text}"))
        else:
            res_json = res.json()
            url = f"{project.web_url}/-/issues/{issue_id}#note_{res_json['id']}"
            save_notification(Notification(project.id, NotificationMedium.GITLAB_ISSUE, step,
                                            url=url, details=res_json['body']))

# Move a project to the GitWalker purgatory namespace
def move_to_purgatory(project: ProjectWithFindings, step: NotificationStep) -> bool:
    logging.debug(f"{dryruntag()}Moving project {project.path} ({project.gitlab_project_id}) to purgatory namespace")
    if not app_config.get('dry_run'):
        try:
            # Transfer the project to the purgatory namespace
            target_namespace = os.environ['GITLAB_PURGATORY_GROUP_ID']
            res = requests.put(
                f"{os.environ['GITLAB_HOST']}/api/v4/projects/{project.gitlab_project_id}/transfer",
                json={'namespace': os.environ['GITLAB_PURGATORY_GROUP_ID']},
                headers={"PRIVATE-TOKEN": os.environ['GITLAB_ADMIN_TOKEN']}
            )

            if res.status_code != 200:
                logging.error(f"Failed to transfer project {project.path} ({project.gitlab_project_id}) to purgatory: {res.text}")
                save_notification(Notification(project.id, NotificationMedium.GITLAB_ISSUE, step,
                                    error=f"Failed to transfer to purgatory: {res.text}"))
                return False
            else:
                res_json = res.json()
                logging.info(f"Project {project.path} ({project.gitlab_project_id}) transferred to purgatory namespace")
                save_notification(Notification(project.id, NotificationMedium.GITLAB_ISSUE, step,
                                    url=res_json['web_url'], details=f"Transferred project to {target_namespace}"))

                # Remove every members from the project
                members = get_project_members(project.gitlab_project_id)
                logging.info(f"Removing all members from project {project.path} ({project.gitlab_project_id})")
                for member in members:
                    res = requests.delete(
                        f"{os.environ['GITLAB_HOST']}/api/v4/projects/{project.gitlab_project_id}/members/{member['id']}",
                        headers={"PRIVATE-TOKEN": os.environ['GITLAB_ADMIN_TOKEN']}
                    )
                    if res.status_code != 204:
                        logging.error(f"Failed to remove member {member['username']} from project {project.path} ({project.gitlab_project_id}): {res.text}")
                        save_notification(Notification(project.id, NotificationMedium.GITLAB_ISSUE, step,
                                        error=f"Failed to remove member {member['username']}: {res.text}"))
                    logging.debug(f"Member {member['username']} removed from project {project.path} ({project.gitlab_project_id})")

                return True
        except Exception as e:
            logging.error(f"Exception when transferring project {project.path} to purgatory: {str(e)}")
            return False
    return True  # In dry run mode, just return True without actual transfer

def main():
    if app_config.get('dump_users'):
        dump_users()
    elif app_config.get('update_rules'):
        update_rules()
    elif app_config.get('notify'):
        analysis_id = get_last_analysis()
        if not analysis_id:
            raise RuntimeError("No analysis found")

        logging.info(f"Notifications limited to {app_config.get('max')} projects (use option --max to change it)")

        if app_config.get('notify') == 'forks':
            match app_config.get('step'):
                case 'second':
                    step = NotificationStep.FORK_2
                case 'purgatory':
                    step = NotificationStep.FORK_PURGATORY
                case _:
                    step = NotificationStep.FORK_1
            notify_forked_projects(analysis_id, step)
        elif app_config.get('notify') == 'teams':
            match app_config.get('step'):
                case 'second':
                    raise NotImplementedError("Not implemented yet.")
                case _:
                    step = NotificationStep.TEAMS_1
            notify_teams_projects(analysis_id, step)

cmd = cmd + [url, os.environ['CLONE_REPOSITORY']]
subprocess.run(cmd, check=True) # nosymbiotic: SYM_PY_0035, SYM_PY_0044