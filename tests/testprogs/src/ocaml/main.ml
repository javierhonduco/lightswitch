let sink = ref 0

let[@inline never] top1 () =
  for i = 1 to 10_000 do
    sink := !sink + i
  done;
  !sink

let[@inline never] c1 () = top1 () + 1

let[@inline never] b1 () = c1 () + 1

let[@inline never] a1 () = b1 () + 1

let[@inline never] top2 () =
  for i = 1 to 10_000 do
    sink := !sink + i
  done;
  !sink

let[@inline never] c2 () = top2 () + 1

let[@inline never] b2 () = c2 () + 1

let[@inline never] a2 () = b2 () + 1

let () =
  while true do
    ignore (a1 ());
    ignore (a2 ())
  done
