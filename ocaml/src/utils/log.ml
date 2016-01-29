(** log facilities *)

let logfid = ref stdout

(** open the given log file *)
let init logfile =
  try
    logfid = open_out logfile
  with
    _ -> Printf.eprintf "Impossible to open the log file. Output will be on stdout\n"
			
let from_analysis module_name msg = Printf.fprintf (!logfid) "%s: %s\n" module_name msg

(** close the log file *)
let close () = close !logfid
