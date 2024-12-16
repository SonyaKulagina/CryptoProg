CXX = g++
CXXFLAGS = -std=c++11 -I/usr/include/cryptopp
LDFLAGS = -L/usr/lib -lcryptopp

TARGET = hash
SOURCES = hash.cpp

all: $(TARGET)

$(TARGET): $(SOURCES)
	$(CXX) $(CXXFLAGS) -o $(TARGET) $(SOURCES) $(LDFLAGS)

clean:
	rm -f $(TARGET)
