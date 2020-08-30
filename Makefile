CXX= c++
CXXFLAGS= -Wall --std=c++17 -O3

all: side_channel spectre_v1

side_channel: side_channel/side_channel.o
	$(CXX) $(CXXFLAGS) -o side_channel.exe side_channel/side_channel.o

spectre_v1: spectre_v1/spectre_v1.o
	$(CXX) $(CXXFLAGS) -o spectre_v1.exe spectre_v1/spectre_v1.o

clean:
	rm -f side_channel.exe spectre_v1.exe side_channel/*.o spectre_v1/*.o