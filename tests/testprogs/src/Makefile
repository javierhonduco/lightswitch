# Try to use gfortran 13 or higher for these tests, as it's the first version
# to support no inlining upon request

F77 := gfortran
FOPTS := -g -mstackrealign -march=westmere -mstackrealign -mfpmath=sse \
				-fasynchronous-unwind-tables -std=legacy -Wall \
				-Wno-overwrite-recursive -fimplicit-none -fdec -frecursive \
				-fno-automatic -fno-range-check -fno-align-commons \
				-fd-lines-as-comments -static-libgfortran \
				-fallow-invalid-boz -fallow-argument-mismatch

F77_SRC := basic_stack.FOR

bins_f77 := basic_stack_f77-O0    basic_stack_f77-O0-noinline \
						basic_stack_f77-O1    basic_stack_f77-O1-noinline \
						basic_stack_f77-O2    basic_stack_f77-O2-noinline \
						basic_stack_f77-O2-fp basic_stack_f77-O2-fp-noinline \
						basic_stack_f77-O3    basic_stack_f77-O3-noinline \
						basic_stack_f77-O3-fp basic_stack_f77-O3-fp-noinline

all: $(bins_f77)

basic_stack_f77-O0: $(F77_SRC)
	$(F77) $(FOPTS) -O0 -o $@ $<

basic_stack_f77-O0-noinline: $(F77_SRC)
	$(F77) -DNOINLINE $(FOPTS) -O0 -o $@ $<

basic_stack_f77-O1: $(F77_SRC)
	$(F77) $(FOPTS) -O1 -o $@ $<

basic_stack_f77-O1-noinline: $(F77_SRC)
	$(F77) -DNOINLINE $(FOPTS) -O1 -o $@ $<

basic_stack_f77-O2: $(F77_SRC)
	$(F77) $(FOPTS) -O2 -o $@ $<

basic_stack_f77-O2-noinline: $(F77_SRC)
	$(F77) -DNOINLINE $(FOPTS) -O2 -o $@ $<

basic_stack_f77-O2-fp: $(F77_SRC)
	$(F77) $(FOPTS) -O2 -fno-omit-frame-pointer -o $@ $<

basic_stack_f77-O2-fp-noinline: $(F77_SRC)
	$(F77) -DNOINLINE $(FOPTS) -O2 -fno-omit-frame-pointer -o $@ $<

basic_stack_f77-O3: $(F77_SRC)
	$(F77) $(FOPTS) -O3 -o $@ $<

basic_stack_f77-O3-noinline: $(F77_SRC)
	$(F77) -DNOINLINE $(FOPTS) -O3 -o $@ $<

basic_stack_f77-O3-fp: $(F77_SRC)
	$(F77) $(FOPTS) -O3 -fno-omit-frame-pointer -o $@ $<

basic_stack_f77-O3-fp-noinline: $(F77_SRC)
	$(F77) -DNOINLINE $(FOPTS) -O3 -fno-omit-frame-pointer -o $@ $<

.PHONY : clean
clean:
	rm $(bins_f77)
