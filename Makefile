SRC_DIR = src/java
RES_DIR = src/resources
BUILD_DIR = build
BUILD_BIN = $(BUILD_DIR)/bin

JAR_PATH = $(BUILD_DIR)/bcalc.jar
MANIFEST = manifest

LIB_PATH = $(HOME)/.sessx/lib

GSON_VER = 2.11.0
GSON_URL = https://repo1.maven.org/maven2/com/google/code/gson/gson/$(GSON_VER)/gson-$(GSON_VER).jar
GSON_PATH = $(LIB_PATH)/gson-$(GSON_VER).jar
GSON_TARGET = $(BUILD_DIR)/gsonok

#JLINE_VER = 3.26.3
#JLINE_URL = https://repo1.maven.org/maven2/org/jline/jline/$(JLINE_VER)/jline-$(JLINE_VER).jar
#JLINE_PATH = $(LIB_PATH)/jline-$(JLINE_VER).jar
#JLINE_TARGET = $(BUILD_DIR)/jlineok

JAVAC = javac
JAVAC_FLAGS = -d $(BUILD_BIN) -sourcepath $(SRC_DIR) -cp $(BUILD_BIN)

JAR = jar
JAR_FLAGS = -cvfm $(JAR_PATH) $(MANIFEST) -C $(BUILD_BIN) .

SOURCES = $(shell find $(SRC_DIR) -name "*.java")
CLASSES = $(SOURCES:$(SRC_DIR)/%.java=$(BUILD_BIN)/%.class)

ASSETS = $(shell find $(RES_DIR) -type f)
ASSETS_TARGETS = $(ASSETS:$(RES_DIR)/%=$(BUILD_BIN)/%)

# default target
all: jar

# gson download
$(GSON_PATH):
	mkdir -p $(LIB_PATH)
	wget -O $(GSON_PATH) $(GSON_URL)
	rm -f $(GSON_TARGET)

# gson unzip
$(GSON_TARGET):
	mkdir -p $(BUILD_BIN)
	unzip -o $(GSON_PATH) -d $(BUILD_BIN)
	touch $(GSON_TARGET)

## jline download
#$(JLINE_PATH):
#	mkdir -p $(LIB_PATH)
#	wget -O $(JLINE_PATH) $(JLINE_URL)
#	rm -f $(JLINE_TARGET)

## jline unzip
#$(JLINE_TARGET):
#	mkdir -p $(BUILD_BIN)
#	unzip -o $(JLINE_PATH) -d $(BUILD_BIN)
#	touch $(JLINE_TARGET)

# libs
lib: $(GSON_PATH) $(GSON_TARGET) #$(JLINE_PATH) $(JLINE_TARGET)

# javac
$(BUILD_BIN)/%.class: $(SRC_DIR)/%.java
	mkdir -p $(dir $@)
	$(JAVAC) $(JAVAC_FLAGS) $<

compl: lib $(CLASSES)

# copy README.md
$(BUILD_BIN)/README.md: README.md
	cp README.md $(BUILD_BIN)/

# copy LICENSE
$(BUILD_BIN)/LICENSE: LICENSE
	cp LICENSE $(BUILD_BIN)/

# jar
$(JAR_PATH): compl $(BUILD_BIN)/README.md $(BUILD_BIN)/LICENSE
	rm -f $(JAR_PATH)
	$(JAR) $(JAR_FLAGS)

jar: $(JAR_PATH)

# clean
.PHONY: clean cleanall
clean:
	rm -rf $(BUILD_DIR)
cleanall: clean
	rm -rf $(LIB_PATH)

