(* Unsafe OCaml Code Examples to Trigger Vulnerability Scanners *)

(* Unsafe deserialization using Marshal.from_channel *)
let _ =
  let ic = open_in "malicious_data.mar" in
  let data = Marshal.from_channel ic in
  close_in ic;
  Printf.printf "Loaded: %s\n" (Obj.magic data : string)

(* Insecure use of Sys.command without sanitizing input *)
let _ =
  let user_input = read_line () in
  let cmd = "ls " ^ user_input in
  ignore (Sys.command cmd)

(* Unsafe file permissions and handling *)
let _ =
  let oc = open_out "sensitive.txt" in
  output_string oc "secret content";
  close_out oc
