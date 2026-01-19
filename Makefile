CC = gcc
CFLAGS = -Wall -Wextra -O2 -Wno-deprecated-declarations
LDFLAGS = -lssl -lcrypto

# Main Hub
HUB_SRCS = hub_main.c hub_config.c hub_crypto.c hub_logic.c hub_storage.c
HUB_OBJS = $(HUB_SRCS:.c=.o)

# Admin Tool
ADM_SRCS = hub_admin.c hub_crypto.c
ADM_OBJS = $(ADM_SRCS:.c=.o)

all: irchub hub_admin

irchub: $(HUB_OBJS)
	$(CC) $(CFLAGS) -o irchub $(HUB_OBJS) $(LDFLAGS)

hub_admin: $(ADM_OBJS)
	$(CC) $(CFLAGS) -o hub_admin $(ADM_OBJS) $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f *.o irchub hub_admin
