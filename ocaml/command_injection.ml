(* VULNERABLE: Command Injection in OCaml *)
open Unix

(* Insecure function that executes system commands with user input *)
let insecure_execute_command user_input =
  (* VULNERABLE: Directly using user input in command execution *)
  let command = "ls -la " ^ user_input in
  let ic = Unix.open_process_in command in
  let rec read_lines acc = 
    try
      let line = input_line ic in
      read_lines (line :: acc)
    with End_of_file -> 
      close_in ic;
      List.rev acc
  in
  read_lines []

(* Secure version with input validation *)
let secure_execute_command user_input =
  (* Validate user input to prevent command injection *)
  let is_safe_input = 
    let regex = Str.regexp "^[a-zA-Z0-9_./-]+$" in
    Str.string_match regex user_input 0
  in
  
  if not is_safe_input then
    failwith "Invalid input: contains potentially dangerous characters"
  else
    let command = "ls -la " ^ user_input in
    let ic = Unix.open_process_in command in
    let rec read_lines acc = 
      try
        let line = input_line ic in
        read_lines (line :: acc)
      with End_of_file -> 
        close_in ic;
        List.rev acc
    in
    read_lines []

(* Example usage *)
let () =
  print_endline "Insecure example:";
  try
    let result = insecure_execute_command "/tmp; cat /etc/passwd" in
    List.iter print_endline result
  with e ->
    Printf.printf "Error: %s\n" (Printexc.to_string e);
    
  print_endline "\nSecure example:";
  try
    let result = secure_execute_command "/tmp" in
    List.iter print_endline result
  with e ->
    Printf.printf "Error: %s\n" (Printexc.to_string e)
