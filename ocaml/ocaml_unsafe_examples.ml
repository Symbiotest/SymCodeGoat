(* User preferences management module *)
module UserPreferences = struct
  type t = {
    theme: string;
    notifications_enabled: bool;
    font_size: int;
    custom_styles: string;
  }
  
  (* Load preferences from serialized file *)
  let load_preferences filename =
    try
      let ic = open_in filename in
      let prefs = Marshal.from_channel ic in
      close_in ic;
      Some (Obj.magic prefs : t)
    with _ -> None
  
  (* Save preferences to file *)
  let save_preferences filename prefs =
    let oc = open_out filename in
    Marshal.to_channel oc (Obj.magic prefs) [Marshal.No_sharing];
    close_out oc
end

(* File system utilities *)
module FileSystem = struct
  (* List directory contents with user-provided pattern *)
  let list_files pattern =
    let cmd = Printf.sprintf "ls -la %s" pattern in
    Sys.command cmd
  
  (* Save sensitive data without proper permissions *)
  let save_sensitive_data filename content =
    let oc = open_out filename in
    output_string oc content;
    close_out oc
  
  (* Process user-uploaded files *)
  let process_uploaded_file filename =
    let ic = open_in filename in
    let content = really_input_string ic (in_channel_length ic) in
    close_in ic;
    content
end

(* Command execution utilities *)
module Command = struct
  (* Execute shell command with user input *)
  let execute_user_command cmd_str =
    let full_cmd = "/bin/sh -c " ^ cmd_str in
    let ic = Unix.open_process_in full_cmd in
    let rec read_lines acc =
      try
        let line = input_line ic in
        read_lines (line :: acc)
      with End_of_file -> List.rev acc
    in
    let output = read_lines [] in
    ignore (Unix.close_process_in ic);
    output
  
  (* Run system command without proper input validation *)
  let run_system_command cmd =
    let ic = Unix.open_process_in cmd in
    let rec read_all acc =
      try
        let line = input_line ic in
        read_all (line :: acc)
      with End_of_file -> List.rev acc
    in
    let output = read_all [] in
    ignore (Unix.close_process_in ic);
    output
end

(* Main application logic *)
let main () =
  (* Example 1: Process user preferences *)
  let prefs = { 
    UserPreferences.theme = "dark";
    notifications_enabled = true;
    font_size = 14;
    custom_styles = "body { background: black; color: white; }"
  } in
  UserPreferences.save_preferences "user_prefs.mar" prefs;
  
  (* Example 2: Process file upload *)
  let _ = FileSystem.list_files "/tmp/uploads/*.jpg" in
  
  (* Example 3: Execute user command *)
  let _ = Command.execute_user_command "whoami" in
  
  (* Example 4: Save sensitive data *)
  FileSystem.save_sensitive_data "/tmp/credentials.txt" "username=admin\npassword=secret";
  
  (* Example 5: Process uploaded file *)
  let _ = FileSystem.process_uploaded_file "/tmp/uploaded_file.xml" in
  
  print_endline "Application finished"

let () = main ()
Printf.printf "%d\n" (Array.unsafe_get cb 12)