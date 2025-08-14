<?php
include("../assets/all/conf.php");

$dbconn = pg_connect("host=sql.vptech.eu dbname=veepwnd user=veepwnd password=D]sdf6]{d3fddJ6GH#") 
    or die('Could not connect: ' . pg_last_error());

$email = $_POST['username'];
$password = $_POST['password'];

$query = "SELECT id, email, password, is_admin FROM users WHERE email = '$email' AND password = '$password'";
error_log("[DEBUG] query: $query");

$result = pg_query($dbconn, $query) or die('Query failed: ' . pg_last_error());
$row = pg_fetch_row($result);

$return = [];
if ($row) {
    $return["ok"] = true;
    $return["email"] = $row[1];
    $_SESSION["usersession"] = [
        "id" => $row[0],
        "is_admin" => $row[3]
    ];
} else {
    $return["ok"] = false;
    $return["query"] = $query;
}

echo json_encode($return);
?>

<li id="search" class="dropdown">
    <form id="search-form" autocomplete="off" action="<?php echo SiteController::URL_GLOBAL_SEARCH ?>">
        <div class="form-group has-feedback">
            <?php
            $q = isset($_GET['q']) ? htmlentities($_GET['q']) : '';
            ?>
            <input id="q" name="q" type="text" value="<?php echo $q ?>" class="form-control"
                placeholder="<?= Yii::t('frontend', 'app.search') ?>">
            <span class="fa fa-search fa-lg form-control-feedback" style="z-index: 1;"></span>
        </div>
    </form>
</li>

<script>
    $(document).ready(function () {