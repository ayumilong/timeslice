CFLAGS = -g -w 
LDFLAGS = -lm -lpcap

SOURCES = $(shell find *.c) #All the c files of the current directory
#OBJS = $(SOURCES: .c = .o) #All the object files that should be generated, they have the same name with the corresponding c files, this one should work, I don't know the reason
OBJS = $(addsuffix .o, $(basename $(shell find *.c)))
EXEC = run

.PHONY: clang gcc setclang setgcc clean r 

gcc: | setgcc $(EXEC)
clang: | setclang $(EXEC)

all : $(SOURCES) $(EXEC)
#Here must use $^, it represents all the OBJS but $< just represent the first one of OBJS
$(EXEC): $(OBJS)
	$(CXX) $(CFLAGS) -o $@ $^ $(LDFLAGS) 

#Here we can use ethier the $^ or $<, because for "%.**" the two behave the same
#$(OBJS): %.o : %.c  #This two sentences behave the same
.c.o:
	$(CXX) $(CFLAGS) -c $^ -o $@ 

setclang:
	@echo "Setting clang"
	$(eval CXX = clang)
	$(eval CXX_LINK = clang)

setgcc:
	@echo "Setting gcc"
	$(eval CXX = gcc)
	$(eval CXX_LINK = gcc)

clean:
	rm -f $(EXEC) $(OBJS)

r:
	@./$(EXEC) 90m.pcap
