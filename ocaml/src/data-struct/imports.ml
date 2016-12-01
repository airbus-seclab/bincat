module Make(D: Domain.T) =
struct
  type fun_type = {
        name: string;
        libname: string;
        prologue: Asm.stmt list;
        stub: Asm.stmt list;
        epilogue: Asm.stmt list
  }

  let tbl: (Data.Address.t, fun_type) Hashtbl.t = Hashtbl.create 5
end
