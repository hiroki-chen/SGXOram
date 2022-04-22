all: sgx_enable

$(CURDIR)/%.o: ../check_sgx/%.c
	@$(CC) -c $< 

sgx_enable: $(CURDIR)/sgx_enable.o
	@$(CC) -o $(CURDIR)/bin/$@.bin $?

clean:
	@rm -f $(CURDIR)/*.o $(CURDIR)/sgx_enable
