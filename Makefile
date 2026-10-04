# PacRipper GNU Make build
# Created by Jacob Hodgkins
CXX ?= g++
CXXFLAGS ?= -O2 -DNDEBUG -std=c++17
CPPFLAGS ?= -Isrc
FS_LIB ?= -lstdc++fs
STRICT_CXXFLAGS := -O2 -DNDEBUG -std=c++17 -Wall -Wextra -Wpedantic -Werror

CORE_SOURCES := $(shell sed '/^[[:space:]]*$$/d' config/core_sources.txt)
CORE_OBJECTS := $(patsubst src/%.cpp,obj/core_make/%.o,$(CORE_SOURCES))
CORE_MAIN_OBJECT := obj/core_make/pacripper_core_main.o

.PHONY: all clean test release-build release-check
all: bin/PacRipperCore bin/PacRipper

bin/PacRipperCore: $(CORE_OBJECTS) $(CORE_MAIN_OBJECT)
	@mkdir -p $(@D)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(FS_LIB)

bin/PacRipper: src/main.cpp
	@mkdir -p $(@D)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -o $@ $< $(FS_LIB)

obj/core_make/%.o: src/%.cpp
	@mkdir -p $(@D)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -c $< -o $@

$(CORE_MAIN_OBJECT): src/pacripper_core_main.cpp
	@mkdir -p $(@D)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -c $< -o $@

release-build:
	$(MAKE) clean
	$(MAKE) CXXFLAGS="$(STRICT_CXXFLAGS)" all

release-check: release-build
	python3 -m compileall -q scripts
	python3 scripts/release_terminology_audit.py .
	python3 scripts/test_archive_safety.py
	@echo "PacRipper V1.0 local release gates: PASS"

clean:
	rm -rf obj/core_make obj/macos bin/PacRipper bin/PacRipperCore bin/PacRipper.exe bin/PacRipperCore.exe
