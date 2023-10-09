MASTER_KEY = "ft_otp.key"

TESTS = tests

SRCS = srcs

OTP_LOG = otp.log

.PHONY: all
all: install
	pip install -e .

.PHONY: clean
clean: 
	@/bin/rm -rf $(OTP_LOG)

.PHONY: fclean
fclean: clean
	@/bin/rm -rf $(MASTER_KEY)
    
.PHONY: re
re: fclean all
    
.PHONY: test
test: 
	pytest $(TESTS)/*

.PHONY: black
black:
	black $(SRCS) $(TESTS)

.PHONY: install
install:
	pip3 install -r requirements.txt

