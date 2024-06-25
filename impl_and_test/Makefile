CC = gcc
CFLAGS = -I./src #  -Wall

BIN_DIR = ./bin
SRC_DIR = ./src
TEST_DIR = ./test

# �?保目标文件目录存�?
# $(BIN_DIR):
# 	mkdir -p $(BIN_DIR)

# 定义各个测试的目�?
TESTS = test_eea3 test_eia3 test_zuc

all: $(TESTS)

# $@: target, $^: all independents, $<: first independent(use when independents declare like "*.c")
test_eea3: $(TEST_DIR)/test_eea3.c $(SRC_DIR)/zuc.c $(SRC_DIR)/eea3.c | $(BIN_DIR)
	$(CC) $(CFLAGS) -o $(BIN_DIR)/$@ $^

test_eia3: $(TEST_DIR)/test_eia3.c $(SRC_DIR)/zuc.c  $(SRC_DIR)/eia3.c | $(BIN_DIR)
	$(CC) $(CFLAGS) -o $(BIN_DIR)/$@ $^

test_zuc: $(TEST_DIR)/test_zuc.c $(SRC_DIR)/zuc.c | $(BIN_DIR)
	$(CC) $(CFLAGS) -o $(BIN_DIR)/$@ $^

clean:
	rm -rf $(BIN_DIR)/*

.PHONY: all clean
