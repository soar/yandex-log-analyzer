# Introduction

This was my test task, written for technical interview for DevOps position in Yandex in 2016. A year has passed and I think I can publish this code.

You can find task description in [statement.pdf](statement.pdf) and sample files in [sample-files.7z](sample-files.7z) archive.

# Usage

```bash
./yandex-log-analyzer.py --help
usage: yandex-log-analyzer.py [-h] [--debug] [--infile input.txt]
                              [--outfile output.txt]

Simple Log Analyzer

optional arguments:
  -h, --help            show this help message and exit
  --debug               Enable debug logging and output report to stdout
  --infile input.txt    Input file to analyze
  --outfile output.txt  File to write report
```

To run this "tool" you need Python 2. Extract archive with sample files and run analyzer on them:

```bash
./yandex-log-analyzer.py --infile sample-files/001.in --outfile sample-files/001.txt
``` 

# Пояснения

* Код может показаться немного странным, т.к. я сначала допустил очень важное упущение: не учёл, что к одной группе и одному бекенду могут быть паралелльные запросы. В результате всё, касающееся оценки здоровья бекенда пришлось вырезать.
* Вначале для парсинга лога я использовал регулярные выражения, но отказался от них в пользу обычного `split`. Думаю, если бы формат лога был сложнее - я бы всё-таки их оставил.
* Поначалу для расчёта 95го перцентиля я использовал NumPy:  
  ```
  numpy.percentile(numpy.array(self.full_request_time), 95)  
  ```
  
  Но, во-первых, это не pure-python модуль, а во-вторых тащить 4-х мегабайтную библиотеку ради одной строки мне показалось излишним.
  
  Да, я понимаю, что мой метод расчёта не математический, но усложнять код мне показалось излишним, тем более статистическая погрешность - минимальна.
  
  И да, мой вариант в два раза медленнее, но, опять же, считаю это приемлимым, учитывая, что NumPy это всё-таки C и соревноваться с ним было бы сложно.
  
  ```
  >>> timeit.timeit('numpy.percentile(numpy.array(a), 95)', 'import random; import numpy; a = random.sample(xrange(1000), 1000)')
  82.83693344616162
  >>> timeit.timeit('sorted(a)[int(round(len(a) * 0.95))-1]', 'import random; a = random.sample(xrange(1000), 1000)')
  161.7847877912875
  ```
