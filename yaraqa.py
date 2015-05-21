#!/usr/bin/env python

from  __future__ import division

import logging
import requests
import datetime
import ConfigParser
import argparse
import os
import yara
import re
import sys
import json
import time

try:
    import pygal
    from pygal.style import Style
    pygal_available = True
except ImportError:
    raise ImportError("Could not import pygal. Yaraqa is not going to generate plots.")
    pygal_available = False


class YaraQA():

    @property
    def logger(self):
        name = 'yaraqa'
        return logging.getLogger(name)

    def __init__(self, family, config_file='yaraqa.conf', method='ALL', malware=True, goodware=True, verbose=False, nolog=False, show=False, plot=False, targeted=False, timeout=15):
        '''
        This method constructs a yaraqa object.
        '''
        #  Default behaviour: ./yaraqa.py [family] --static --memory --malware --goodware

        self.GOODWARE_DIR = ''
        self.MALWARE_DIR = ''
        self.YARA_STATIC_DIR = ''
        self.YARA_MEMORY_DIR = ''
        self.API_PATH = ''
        self.API_PORT = ''
        self.API_HOST = ''
        self.API_IP = ''

        self.HIGH_THRESHOLD = '' 
        self.MEDIUM_THRESHOLD = ''

        self.PLOT_LABELS = []
        self.PLOT_STATIC_RATIOS = []
        self.PLOT_MEMORY_RATIOS = []
        self.PLOT_TOTAL_MATCH = []

        self.nolog = nolog
        
        if not family:
            self.die("--family must be set")

        self.family = family.lower()
        self.show = show
        if self.show:
                self.show_available()

        self.method = method
        self.malware = malware
        self.goodware = goodware
        self.verbose = verbose
        
        if timeout < 0:
            self.die("Timeout cannot be less than zero")
        self.timeout = timeout

        self.targeted = targeted
        self.plot = plot

        self.LOGGING = True
        if self.nolog:
            self.LOGGING = False
        self.init_logging()

        if self.method:
            self.method = method.upper()
            if self.method != 'STATIC' and self.method != 'MEMORY' and self.method != 'ALL':
                self.die("Method is not valid. Valid methods: MEMORY, STATIC, ALL.")

        self.config_file = config_file
        self.parse_config()

        self.DIRECTORIES = []
        if self.malware:
            self.DIRECTORIES.append(self.MALWARE_DIR)
        if self.goodware:
            self.DIRECTORIES.append(self.GOODWARE_DIR)
        if not self.goodware and not self.malware:
            self.DIRECTORIES.append(self.MALWARE_DIR)
            self.DIRECTORIES.append(self.GOODWARE_DIR)

    def die(self, m):
        '''
        This method logs a critical message and exits yaraqa.py
        '''
        self.logger.critical(m)
        sys.exit()

    def init_yara_rules(self):
        '''
        This method tries to find and compile the yara rules specified by 'family' before the q&a test starts.
        '''
        if (self.method == 'STATIC' or self.method == 'ALL'):
            if not os.path.isfile(self.YARA_STATIC_DIR+self.family+'.yara'):
                yara_path = self.YARA_STATIC_DIR+self.family+'.yara'
                self.die("Can't found static yaras for this family! {0}".format(str(yara_path)))
            yara_path = self.YARA_STATIC_DIR+self.family+'.yara'
            rule_static = yara.compile(filepath=yara_path)
            if not rule_static:
                self.die("Couldn't compile the .yara! {0}".format(str(yara_path)))

        if (self.method == 'MEMORY' or self.method == 'ALL'):
            if not os.path.isfile(self.YARA_MEMORY_DIR+self.family+'.yara'):
                yara_path = self.YARA_MEMORY_DIR+self.family+'.yara'
                self.die("Can't found memory yaras for this family! {0}".format(str(yara_path)))
            yara_path = self.YARA_MEMORY_DIR+self.family+'.yara'
            rule_memory = yara.compile(filepath=yara_path)
            if not rule_memory:
                self.die("Couldn't compile the .yara! {0}".format(str(yara_path)))

        if (self.method == 'STATIC' or self.method == 'ALL'):
            return rule_static
        else:
            return rule_memory

    def init_logging(self):
        '''
        This method establishes the logging configs. properly.
        '''
        self.logger.setLevel(logging.DEBUG)

        if not self.logger.handlers:

            consoleHandler = logging.StreamHandler()
            consoleHandler.setLevel(logging.CRITICAL)

            if self.LOGGING:
                if not os.path.exists('reports'):
                    os.makedirs('reports')
                daytime = datetime.datetime.now().strftime("%d%m%Y_%H_%M_%S")
                logname = "reports/report_{}_{}.log".format(self.family,daytime)
                fileHandler = logging.FileHandler(logname)
                fileHandler.setLevel(logging.DEBUG)
                self.logger.addHandler(fileHandler)

            if self.verbose:
                consoleHandler.setLevel(logging.DEBUG)

            self.logger.addHandler(consoleHandler)

    def request_api(self):
        '''
        This method makes a simple request to the API to see whether it's working or not.
        '''
        try:
            r = requests.get('http://{0}:{1}/cuckoo/status'.format(str(self.API_IP), str(self.API_PORT)))
        except requests.exceptions.RequestException as err:
            self.die(err)
        except Exception as err:
            self.die(err)

    def parse_config(self):
        '''
        This method tries to parse yaraqa.conf file in order to setup config.
        '''
    
        if os.path.isfile(self.config_file):
            if not os.access(self.config_file, os.R_OK):
                self.die("Cannot read {0} configuration file".format(str(self.config_file)))
        else:
            self.die("Cannot find {0} configuration file".format(str(self.config_file)))

        try:
            config_parser = ConfigParser.ConfigParser()
            configFilePath = self.config_file
            config_parser.read(configFilePath)
            self.GOODWARE_DIR = config_parser.get('SAMPLES_DIR', 'goodware_path').replace('"', '')
            self.MALWARE_DIR = config_parser.get('SAMPLES_DIR', 'malware_path').replace('"', '')
            self.YARA_STATIC_DIR = config_parser.get('YARA_DIR', 'yara_static_path').replace('"', '')
            self.YARA_MEMORY_DIR = config_parser.get('YARA_DIR', 'yara_memory_path').replace('"', '')
            self.API_PATH = config_parser.get('CUCKOO_API', 'api_path').replace('"', '')
            self.API_HOST = config_parser.get('CUCKOO_API', 'api_host').replace('"', '')
            self.API_PORT = config_parser.get('CUCKOO_API', 'api_port').replace('"', '')
            self.API_IP = config_parser.get('CUCKOO_API', 'api_ip').replace('"', '')
            self.HIGH_THRESHOLD = config_parser.get('THRESHOLD_LEVELS', 'high_threshold').replace('"', '')
            self.MEDIUM_THRESHOLD = config_parser.get('THRESHOLD_LEVELS', 'medium_threshold').replace('"', '')

        except ConfigParser.ParsingError as err:
            self.die('Could not parse config: {0}'.format(str(err)))
        except Exception as err:
            self.die('Could not parse config: {0}'.format(str(err)))

    def create_cuckoo_task(self, current_file):
        '''
        This method creates a task at cuckoo by sending a multipart file.
        '''
        try:
            request_url = ('http://{0}:{1}/tasks/create/file'.format(str(self.API_IP), str(self.API_PORT)))
            with open(current_file, "rb") as sample:
                multipart_file = {"file": ("temp_file_name", sample)}
                request = requests.post(request_url, files=multipart_file, timeout=self.timeout)

            if request.status_code != 200:
                self.die("An error ocurred: {} status code".format(request.status_code))

            json_decoder = json.JSONDecoder()
            task_id = json_decoder.decode(request.text)["task_id"]

            return task_id

        except requests.exceptions.RequestException as err:
            self.die(err)
        except Exception as err:
            self.die(err)

    def view_cuckoo_report(self, task_id, tsleep=5):
        '''
        This method retireves the resulting cuckoo's task report
        '''
        try:
            r = requests.get('http://{0}:{1}/tasks/report/{2}'.format(str(self.API_IP), str(self.API_PORT), str(task_id)))
            while r.status_code != 200:
                time.sleep(tsleep)
                r = requests.get('http://{0}:{1}/tasks/report/{2}'.format(str(self.API_IP), str(self.API_PORT), str(task_id)))
            report = json.loads(r.text)
            return report

        except requests.exceptions.RequestException as err:
            self.die(err)
        except Exception as err:
            self.die(err)

    def show_available(self):
        '''
        This method shows all available .yara files at both static and memory yara directories.
        '''
        TOTAL_FILES = 0
        print '\033[0;32m[STATIC YARAS]\033[0m\n'
        for root, dirs, files in os.walk(self.YARA_STATIC_DIR):
            for file in files:
                TOTAL_FILES = TOTAL_FILES + 1
                print "{}".format(file)
        print '\n--->Total Static Yaras: {0}\n'.format(str(TOTAL_FILES))
        TOTAL_FILES = 0
        print '\033[0;32m[MEMORY YARAS]\033[0m\n'
        for root, dirs, files in os.walk(self.YARA_STATIC_DIR):
            for file in files:
                TOTAL_FILES = TOTAL_FILES + 1
                current_file = os.path.join(root, file)
                print "{}".format(file)
        print '\n--->Total Memory Yaras: {0}\n'.format(str(TOTAL_FILES))
        self.die("")

    def print_results(self, method, directory, expected_matches, family_matches, misses, false_positives, total_matches):
        '''
        This method prints the analysis results
        '''
        self.logger.debug("  Expected matches: {0}".format(str(expected_matches)))
        self.logger.debug("  Family matches: {0}".format(str(family_matches)))
        self.logger.debug("  Misses: {0}".format(str(misses)))
        self.logger.debug("  False positives: {0}".format(str(false_positives)))
        self.logger.debug("  Total matches: {0}".format(str(total_matches)))
        if directory == self.MALWARE_DIR:
            if expected_matches != 0:
                ratio = (family_matches/expected_matches)*100
                ratio = "{:.2f}".format(ratio)
                if method == 'STATIC':
                    self.PLOT_STATIC_RATIOS.append(float(ratio))
                if method == 'MEMORY':
                    self.PLOT_MEMORY_RATIOS.append(float(ratio))

                self.print_threshold("  Ratio: ", ratio)



    def print_threshold(self, message, ratio):
        '''
        This method prints with colors depending on the ratio
        '''
        GREEN_COLOR = '\033[1;32m'
        YELLOW_COLOR = '\033[1;33m'
        RED_COLOR = '\033[1;31m'
        BOLD_COLOR = '\033[1;37m'
        END_TAG_COLOR = '\033[0m'

        if float(ratio) >= float(self.HIGH_THRESHOLD):
            self.logger.debug("{0}{1}{2}{3}{4}%{5}\n".format(str(BOLD_COLOR), str(message), str(END_TAG_COLOR), \
                                str(GREEN_COLOR), str(ratio),  str(END_TAG_COLOR)))
        elif float(ratio) >= float(self.MEDIUM_THRESHOLD):
            self.logger.debug("{0}{1}{2}{3}{4}%{5}\n".format(str(BOLD_COLOR), str(message), str(END_TAG_COLOR), \
                                str(YELLOW_COLOR), str(ratio), str(END_TAG_COLOR)))
        else:
            self.logger.debug("{0}{1}{2}{3}{4}%{5}\n".format(str(BOLD_COLOR), str(message), str(END_TAG_COLOR), \
                                str(RED_COLOR), str(ratio),  str(END_TAG_COLOR)))

    def render_plot(self):
        '''
        This method renders a plot in .svg showing yara's accuracy.
        '''
        if not self.PLOT_STATIC_RATIOS:
            self.PLOT_STATIC_RATIOS.append(0)
        if not self.PLOT_MEMORY_RATIOS:
            self.PLOT_MEMORY_RATIOS.append(0)
        if not self.PLOT_TOTAL_MATCH:
            self.PLOT_TOTAL_MATCH.append(0)

        PLOT_COLOR_PINK = '#990033'
        PLOT_COLOR_GREEN = '#66CC33'
        PLOT_COLOR_BLUE = '#006699'

        custom_style = Style(colors=(PLOT_COLOR_PINK, PLOT_COLOR_GREEN, PLOT_COLOR_BLUE))

        bar_chart = pygal.Bar(style=custom_style)
        bar_chart.title = 'Yara Q&A Test'
        bar_chart.title_font_size = 18
        bar_chart.label_font_size = 8
        bar_chart.x_labels = self.PLOT_LABELS
        bar_chart.x_label_rotation = 20
        bar_chart.y_title = '% Matched'
        
        bar_chart.add('STATIC', self.PLOT_STATIC_RATIOS)
        bar_chart.add('MEMORY', self.PLOT_MEMORY_RATIOS)
        bar_chart.add('TOTAL', self.PLOT_TOTAL_MATCH)

        bar_chart.x_labels_major = []
        for i in range(len(self.PLOT_TOTAL_MATCH)):
            if self.PLOT_TOTAL_MATCH[i] == 100:
                bar_chart.x_labels_major.append(bar_chart.x_labels[i])

        timestamp = datetime.datetime.now().strftime("%d%m%Y_%H_%M_%S")
        chartname = 'report_'+timestamp+'.svg'
        bar_chart.render_to_file(chartname)

    def match_yara_rules(self):
        '''
        This method tries to match yara rules at malware and/or goodware repo.
        '''
        rules = self.init_yara_rules()

        self.PLOT_LABELS.append(format(str(self.family)))

        for path in self.DIRECTORIES:

            EXPECTED_MATCHES = 0
            TOTAL_STATIC_MATCHES = 0
            TOTAL_MEMORY_MATCHES = 0
            STATIC_FAMILY_MATCHES = 0
            MEMORY_FAMILY_MATCHES = 0
            STATIC_FALSE_POSITIVES = 0
            MEMORY_FALSE_POSITIVES = 0
            STATIC_MISS = 0
            MEMORY_MISS = 0
            TOTAL_FILES = 0
            TOTAL_MATCHES = 0

            self.logger.debug('Matching against {0}'.format(str(path)))
            self.logger.debug('========================================\n')

            for root, dirs, files in os.walk(path):
                for file in files:

                    current_file = os.path.join(root, file)
                    file_matched = False
                    if self.targeted:
                        if self.family not in current_file:
                            continue

                    TOTAL_FILES = TOTAL_FILES + 1

                    if self.family in current_file:
                        EXPECTED_MATCHES = EXPECTED_MATCHES + 1
                        self.logger.debug('\nTARGET: {0}'.format(str(current_file)))
                    if (self.method == 'STATIC'):
                        matches = rules.match(current_file)
                    elif (self.method == 'MEMORY'):
                        task_id = self.create_cuckoo_task(current_file)
                    else:
                        matches = rules.match(current_file)
                        task_id = self.create_cuckoo_task(current_file)

                    #  MATCH STATIC
                    if (self.method == 'STATIC' or self.method == 'ALL'):
                        if matches:
                            TOTAL_STATIC_MATCHES = TOTAL_STATIC_MATCHES + 1
                            if self.family in current_file:
                                if not file_matched:
                                    TOTAL_MATCHES = TOTAL_MATCHES + 1
                                    file_matched = True
                                STATIC_FAMILY_MATCHES = STATIC_FAMILY_MATCHES + 1
                                self.logger.debug('-> STATIC YARA MATCH {0} \033[0;32m[OK]\033[0m'.format(str(matches)))
                            else:
                                STATIC_FALSE_POSITIVES = STATIC_FALSE_POSITIVES + 1
                                self.logger.debug('FALSE POSITIVE: ' + current_file)
                                self.logger.debug('-> STATIC YARA MATCH {0} \033[0;31m[FALSE POSITIVE]\033[0m'.format(str(matches)))
                        else:
                            if self.family in current_file:
                                STATIC_MISS = STATIC_MISS + 1
                                self.logger.debug('-> STATIC YARA \033[0;31m[MISS]\033[0m')

                    #  MATCH MEMORY
                    if (self.method == 'MEMORY' or self.method == 'ALL'):
                        report = self.view_cuckoo_report(task_id)
                        matched = False
                        rxp = re.compile(self.family, re.IGNORECASE)

                        if report['memory']:
                            if report['memory']['yarascan']:
                                if report['memory']['yarascan']['data']:
                                    matched = any(rxp.search(yar_n['rule']) for yar_n in report['memory']['yarascan']['data'])
                                else:
                                    if self.family in current_file:
                                        self.logger.debug("Warning: No 'data' key found in 'yarascan' section. file = {0}".format(str(current_file)))
                            else:
                                if self.family in current_file:
                                    self.logger.debug("Warning: No 'yarascan' key found in 'memory' section. file = {0}".format(str(current_file)))
                        else:
                                if self.family in current_file:
                                    self.logger.debug("Warning: No 'memory' key found in report data. file = {0}".format(str(current_file)))

                        if matched:
                            TOTAL_MEMORY_MATCHES = TOTAL_MEMORY_MATCHES + 1
                            if self.family in current_file:
                                if not file_matched:
                                    TOTAL_MATCHES = TOTAL_MATCHES + 1
                                    file_matched = True
                                MEMORY_FAMILY_MATCHES = MEMORY_FAMILY_MATCHES + 1
                                self.logger.debug('-> MEMORY YARA MATCH \033[0;32m[OK]\033[0m')
                            else:
                                MEMORY_FALSE_POSITIVES = MEMORY_FALSE_POSITIVES + 1
                                self.logger.debug('FALSE POSITIVE: {0}'.format(str(current_file)))
                                self.logger.debug('-> MEMORY YARA MATCH \033[0;31m[FALSE POSITIVE]\033[0m')
                        else:
                            if self.family in current_file:
                                MEMORY_MISS = MEMORY_MISS + 1
                                self.logger.debug('\033[0;31m[MISS]\033[0m')
 
            if path == self.MALWARE_DIR:
                self.logger.debug('\n\t_MALWARE REPO_')
            elif path == self.GOODWARE_DIR:
                self.logger.debug('\n\t_GOODWARE REPO_')

            if (self.method == 'STATIC' or self.method == 'ALL'):
                self.logger.debug('\n STATIC YARA Q&A OVERVIEW:')       
                self.logger.debug(' =========================')
                self.print_results('STATIC', path, EXPECTED_MATCHES, STATIC_FAMILY_MATCHES, STATIC_MISS, STATIC_FALSE_POSITIVES, TOTAL_STATIC_MATCHES)
            
            if (self.method == 'MEMORY' or self.method == 'ALL'):
                self.logger.debug('\n MEMORY YARA Q&A OVERVIEW:')
                self.logger.debug(' =========================')
                self.print_results('MEMORY', path, EXPECTED_MATCHES, MEMORY_FAMILY_MATCHES, MEMORY_MISS, MEMORY_FALSE_POSITIVES, TOTAL_MEMORY_MATCHES)

            if path == self.MALWARE_DIR:
                if EXPECTED_MATCHES != 0:
                    TOTAL_MATCHES = (TOTAL_MATCHES/EXPECTED_MATCHES)*100
                    TOTAL_MATCHES = "{:.2f}".format(TOTAL_MATCHES)
                    self.PLOT_TOTAL_MATCH.append(float(TOTAL_MATCHES))
            
                    self.print_threshold(" Total Accuracy: ", TOTAL_MATCHES)

            self.logger.debug(" Total files analyzed: {0}\n\n".format(str(TOTAL_FILES)))

        if self.plot:
            if pygal_available:
                self.render_plot()

        DATA_PLOT = [self.PLOT_LABELS, self.PLOT_STATIC_RATIOS, self.PLOT_MEMORY_RATIOS, self.PLOT_TOTAL_MATCH]

        return DATA_PLOT


def parse_arguments():
    '''
    This function parses the arguments recieved by yaraqa.
    '''
    try:
        args = P.parse_args()
    except IOError as e:
        ArgumentParser.error(e)

    if args.memory and not args.static:
        method = 'MEMORY'

    if args.static and not args.memory:
        method = 'STATIC'

    if args.all or (not args.all and not args.static and not args.memory) or (args.static and args.memory):
        method = 'ALL'

    malware_dir = True
    goodware_dir = True
    if not args.malware and args.goodware:
        malware_dir = False
    if not args.goodware and args.malware:
        goodware_dir = False

    DATA = {
        'family': args.family,
        'method': method,
        'malware_dir': malware_dir,
        'goodware_dir': goodware_dir,
        'verbose': args.verbose,
        'nolog': args.nolog,
        'show': args.show,
        'plot': args.plot,
        'timeout': args.timeout,
        'targeted': args.targeted
        }

    return DATA


if __name__ == '__main__':

    P = argparse.ArgumentParser(description=' == Yara Quality Assurance Test ==')
    P.add_argument('--family'   , default=None,         help='Choose a malware familty to Q&A', type=str, required=True)
    P.add_argument('--verbose'  , action='store_true',  help='Be Verbose! =)') 
    P.add_argument('--static'   , action='store_true',  help='Yara static matching only')
    P.add_argument('--memory'   , action='store_true',  help='Yara memory matching only')
    P.add_argument('--all'      , action='store_true',  help='Yara static and memory matching')
    P.add_argument('--show'     , action='store_true',  help='Show available yaras and exit')
    P.add_argument('--malware'  , action='store_true',  help='Match against malware repo.')
    P.add_argument('--goodware' , action='store_true',  help='Match against goodware repo.')
    P.add_argument('--nolog'    , action='store_true',  help='Do not store results in a .log file')
    P.add_argument('--plot'     , action='store_true',  help='Plot matching statistics')
    P.add_argument('--timeout'  , default=15,           help='Timeout for cuckoo memory analysis', type=int)
    P.add_argument('--targeted' , action='store_true',  help='Scan only on targeted files')

    DATA = parse_arguments()

    QA = YaraQA(DATA['family'], 'yaraqa.conf', DATA['method'], DATA['malware_dir'], DATA['goodware_dir'], DATA['verbose'], DATA['nolog'], \
                DATA['show'], DATA['plot'], DATA['targeted'], DATA['timeout'])


    QA.match_yara_rules()
    QA.die('Q&A Finished\n')

