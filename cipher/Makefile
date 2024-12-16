TARGET = cipher
SRCS = cipher.cpp
CXXFLAGS = -std=c++11 -Wall
LDFLAGS = -lcryptopp
all: $(TARGET)
$(TARGET): $(SRCS)
	$(CXX) $(CXXFLAGS) -o $(TARGET) $(SRCS) $(LDFLAGS)
clean:
	rm -f $(TARGET)
