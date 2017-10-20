CC = g++

FLAGS = -Wno-write-strings

TARGET = NetworkPacketAnalyzer

INC_DIR = -I/home/robert-durfee/Libraries/libpcap

LIB_DIR = -L/home/robert-durfee/Libraries/libpcap

LIB = -lpcap

all: $(TARGET)

$(TARGET): $(TARGET).cpp
	$(CC) $(FLAGS) $(INC_DIR) $(LIB_DIR) -o $(TARGET) $(TARGET).cpp $(LIB)

clean:
	$(RM) $(TARGET)
