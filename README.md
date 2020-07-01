# LetMeCheat!
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://github.com/90n20/LetMeCheat/blob/master/LICENSE)

This repository contains a tool developed to help into the research conducted for the master thesis:


<p align="center" style="font-size:larger;">
<i>Let Me Cheat!</i>
</p>
<p align="center" style="font-size:large;">
<i>An analysis of anti-cheat bypass techniques on videogames</i>
</p>

written by David Rodríguez, under the supervision of Sergio Pastrana.

## License
This tool is made available under the GNU General Public License v3.0. A copy of the full license is available in the [LICENSE](/LICENSE) file.

## Installation
The tool is developed with Python version 3.8 and required dependencies could be installed through the command:
```
pip install -r requirements.txt
```

### Dependencies
```
art==4.7
colorama==0.4.3
filetype==1.0.7
future==0.18.2
numpy==1.19.0
pandas==1.0.5
pefile==2019.4.18
python-dateutil==2.8.1
pytz==2020.1
rarfile==3.1
six==1.15.0
tqdm==4.47.0
yara-python==4.0.2
```

#### Extra
The tool is aimed to run into a linux/unix environment. If not avaliable, the following dependencies must be installed:
```
unrar
```


## Usage
Once requirements are installed and ready, samples directories must be configured in the file modules/config.py. In order to execute the tool and generate a csv
report the following command must be launched:

```
python letmecheat.py
```
