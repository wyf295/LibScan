# LibScan

- LibScan is a third-party library (TPL) detection tool for Android apps. Given the list of TPL JARs/DEXs and the Android app(s), it can detect which TPLs (and their versions) are used in the app(s).
------------------------

# Install Dependencies

```
sudo apt install python3-pip
pip install asn1crypto decorator lxml networkx
```
------------------------

# Usage

```
cd tool
python3 LibScan.py detec_all [options]
```
- Please refer to the following command-line options in detail:
```
usage: LibScan.py detect_all [-h] [-o FOLDER] [-p num_processes] [-af FOLDER] [-lf FOLDER] [-ld FOLDER]

optional arguments:
  -h, --help        show this help message and exit
  -o FOLDER         Specify directory of detection results (containing result in .TXT per app)
  -p num_processes  Specify maximum number of processes used in detection (default=#CPU_cores)
  -af FOLDER        Specify directory of apps
  -lf FOLDER        Specify directory of TPL versions
  -ld FOLDER        Specify directory of TPL versions in DEX files
```
- Usage example: For the apks in directory `tool/apks`, detect if each apk contains the TPL versions in `tool/libs` or `tool/libs_dex`.
- User may put the JAR file of TPL into `tool/libs`, or put the DEX file of TPL into `tool/libs_dex`.
```
python3 LibScan.py detect_all -o outputs -af apks -lf libs -ld libs_dex
```
------------------------

# Configurations

The major configurations can be deployed in `module/config.py`
```
# Maximum number of processes used in detection:
max_thread_num = multiprocessing.cpu_count()

# Detection level: ("lib"=TPL level detection; "lib_version"=TPL version level detection)
# Default is TPL version level detection. Need to provide (TPL version,TPL) mapping in `conf/lib_name_map.csv` (We have provide the mapping for the ground truth dataset)
detect_type = "lib_version"

# class similarity threshold (theta)
class_similar = 0.7
# lib similarity threahold (theta2)
lib_similar = 0.85

# Global log configuration (INFO mode by default. Will output the phase-level matching results into log file when using DEBUG mode
logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(name)s - [%(lineno)d] - %(message)s',
                    filename="log.txt",
                    filemode="a+")
LOGGER = logging.getLogger("console")
```
------------------------

# Example

We detect `data/ground_truth_apks/com.linuxcounter.lico_update03.apk` contains which TPL versions in `data/ground_truth_libs`.

Step 1: put `data/ground_truth_apks/com.linuxcounter.lico_update03.apk` into `tool/apks`.

Step 2: put all the library DEX files in `data/ground_truth_libs_dex` into `tool/libs_dex`, or
	pub all the library JAR files in `data/ground_truth_libs` into `tool/libs`.

Step 3: run the following command:
```
python3 LibScan.py detect_all -o outputs -af apks -lf libs -ld libs_dex
```

The detection result is at `tool/outputs/com.linuxcounter.lico_update03.apk.txt`. The content is in the form `(TPL version name, similarity value)` and the detection time cost in the last line.
```
lib: com.android.support.gridlayout-v7.18.0.0
similarity: 1.0

lib: support-v4-18.0.0
similarity: 0.9995847803110373

lib: library-1.0.19 and com.mcxiaoke.volley.library.1.0.19
similarity: 1.0

time: 13s
```

