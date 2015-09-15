(** binding between C and ml *)
(** this module contains all exported symbols *)

(** main function *)
(** the configfile parameter is the configuration file of the analyzer (options, binary code, etc.) *)
(** the resultfile paramter is the filename for the results of the analysis *)
val process: configfile:string -> resultfile: string -> unit
											  

