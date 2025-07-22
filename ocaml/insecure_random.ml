(* VULNERABLE: Insecure random number generation in OCaml *)

(* Insecure random number generation for cryptographic purposes *)
let insecure_token () =
  let chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789" in
  let len = String.length chars in
  let random_char () = chars.[Random.int len] in
  String.init 32 (fun _ -> random_char ())

(* Secure random number generation using cryptographically secure RNG *)
let secure_token () =
  let open Unix in
  let ic = open_in "/dev/urandom" in
  let buf = Bytes.create 32 in
  really_input ic buf 0 32;
  close_in ic;
  let to_hex_char n =
    let n = Char.code n in
    let hex_digit n =
      if n < 10 then Char.chr (n + 48)  (* 0-9 *)
      else Char.chr (n + 87)            (* a-f *)
    in
    [| hex_digit (n lsr 4); hex_digit (n land 0x0f) |]
  in
  let result = Bytes.create 64 in
  for i = 0 to 31 do
    let hex = to_hex_char (Bytes.get buf i) in
    Bytes.set result (i * 2) hex.(0);
    Bytes.set result ((i * 2) + 1) hex.(1)
  done;
  Bytes.to_string result

(* Example usage *)
let () =
  (* Insecure random - predictable and not suitable for security purposes *)
  Random.self_init ();  (* Initializes with weak entropy *)
  let weak_token = insecure_token () in
  Printf.printf "Insecure token: %s\n%!" weak_token;
  
  (* Secure random - uses system's cryptographically secure RNG *)
  let strong_token = secure_token () in
  Printf.printf "Secure token: %s\n%!" strong_token;
  
  (* For cryptographic operations, always use secure random number generation *)
  (* The insecure version can be predicted by an attacker, especially if they can *)
  (* observe multiple tokens or know when the application was started *)
