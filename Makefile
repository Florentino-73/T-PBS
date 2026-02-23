SUB_DIR := server user client

all:
	for dir in $(SUB_DIR); do\
		$(MAKE) -C $$dir; \
	done

clean:
	for dir in $(SUB_DIR); do \
		$(MAKE) -C $$dir clean; \
	done