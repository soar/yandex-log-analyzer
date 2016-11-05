#!/usr/bin/env python
# -*- coding: utf-8 -*-

import argparse
import collections
import heapq
import io
import logging
import numpy

#logentry_re = re.compile(r'(?P<time>\d+)\t(?P<reqid>\d+)\t(?P<type>\w+)(?:\t(?P<groupid>\d+)(?:\t(?P<desc>(.*)))?)?')
#hostname_re = re.compile(r'//(?P<name>[\w\d\-.:]*)/')


class StatsCollector(object):

    def __init__(self):
        self.jobs_without_full_set = 0
        self.full_request_time = []
        self.send_answer_time = {}
        self.active_jobs = {}

    def add_log_entry(self, line):
        """
        Parse string to a dictionary (regexp are too slow for this)
        :param line: str
        """
        ls = line.strip().split('\t')
        logentry = {
            'time': int(ls[0]),
            'reqid': int(ls[1]),
            'type': ls[2]
        }
        if len(ls) > 3:
            logentry['groupid'] = int(ls[3])
        if len(ls) > 4:
            logentry['desc'] = ls[4]
        self.process_log_entry(logentry)

    def get_active_job(self, jobid):
        """
        Access to already logged frontend job
        :param jobid: int
        :return: FrontendJobInfo
        """
        if jobid in self.active_jobs:
            return self.active_jobs[jobid]
        else:
            logging.debug('Trying to access properties of job {0!s}, but no info found'.format(jobid))
            return None

    def process_log_entry(self, logentry):
        """
        Choose right method to process log string by type
        :param logentry: dict
        """
        processor_name = 'process_' + logentry['type'].lower()
        if hasattr(self, processor_name):
            processor = getattr(self, 'process_' + logentry['type'].lower())
            processor(logentry)

    def process_startrequest(self, logentry):
        self.active_jobs.update({logentry['reqid']: FrontendJobInfo(logentry['reqid'], int(logentry['time']))})
        """
        Create record about new Frontend Job
        :param logentry: dict
        """

    def process_startmerge(self, logentry):
        """
        Log time of StartMerge event - looks like not needed
        :param logentry: dict
        """
        job = self.get_active_job(logentry['reqid'])
        if job:
            job.start_merge_time = int(logentry['time'])

    def process_startsendresult(self, logentry):
        """
        Log time of StartSendResult event
        :param logentry: dict
        """
        job = self.get_active_job(logentry['reqid'])
        if job:
            job.start_send_result_time = int(logentry['time'])

    def process_finishrequest(self, logentry):
        """
        On FinishRequest event we need to:
         - Save request time and user response time
         - Check all backend groups for health
         - Remove job information
        :param logentry: dict
        """
        job = self.get_active_job(logentry['reqid'])
        if job:
            job.finish_time = int(logentry['time'])

            full_request_time = job.finish_time - job.start_time
            if full_request_time <= 0:
                logging.debug('Wrong request time found')
            else:
                self.full_request_time.append(full_request_time)

            send_answer_time = job.finish_time - job.start_send_result_time
            if send_answer_time <= 0:
                logging.debug('Wrong send data time found')
            else:
                self.send_answer_time.update({logentry['reqid']: send_answer_time})

            for backend_group in job.backend_groups:
                if not BackendInfo.get_last(backend_group).was_success:
                    self.jobs_without_full_set += 1
                    break

            del self.active_jobs[logentry['reqid']]

    def process_backendconnect(self, logentry):
        """
        Save backend name (host + port) extracted from event comment and count connection.
         Also add backend group to current job relations
        :param logentry: dict
        """
        BackendInfo.get(logentry['groupid'], logentry['desc'].split('/')[2]).count_connect()

        job = self.get_active_job(logentry['reqid'])
        if job:
            job.add_backend_group(logentry['groupid'])

    def process_backendrequest(self, logentry):
        """
        Only count request
        :param logentry: dict
        """
        backend_info = BackendInfo.get_last(logentry['groupid'])
        if backend_info:
            backend_info.count_request()
        else:
            logging.debug("There is no information about last accessed backend in group {0!s}".format(logentry['groupid']))

    def process_backendok(self, logentry):
        """
        Count success request - this marks backend healthy
        :param logentry: dict
        """
        backend_info = BackendInfo.get_last(logentry['groupid'])
        if backend_info:
            backend_info.count_success()
        else:
            logging.debug("There is no information about last accessed backend in group {0!s}".format(logentry['groupid']))

    def process_backenderror(self, logentry):
        """
        Save error got from backend
        :param logentry: dict
        """
        backend_info = BackendInfo.get_last(logentry['groupid'])
        if backend_info:
            backend_info.count_error(logentry['desc'])
        else:
            logging.debug("There is no information about last accessed backend in group {0!s}".format(logentry['groupid']))

    @property
    def results(self):
        """
        Output gathered statistics
        :return: array
        """
        output = []

        na = numpy.array(self.full_request_time)
        output.append(u"95-й перцентиль времени работы: {0!s}\n".format(numpy.percentile(na, 95)))

        longest_answers = heapq.nlargest(10, self.send_answer_time, key=self.send_answer_time.__getitem__)
        output.append(u"Идентификаторы запросов с самой долгой фазой отправки результатов пользователю:")
        for ansid in longest_answers:
            output.append(u"\tЗапрос #{0!s}: {1!s} мкс".format(ansid, self.send_answer_time[ansid]))

        output.append(u"Запросов с неполным набором ответивших ГР: {0!s}\n".format(self.jobs_without_full_set))

        output.append(u"Обращения и ошибки по бекендам:")

        backend_info = BackendInfo.get_all()
        for backend_group in sorted(backend_info):
            output.append(u"ГР {0!s}".format(backend_group))
            for backend in sorted(backend_info[backend_group]):
                output.append(u"\t{0!s}".format(backend))
                output.append(u"\t\tОбращения: {0!s}".format(backend_info[backend_group][backend].connects))
                if backend_info[backend_group][backend].errors:
                    output.append(u"\t\tОшибки:")
                    for error in backend_info[backend_group][backend].errors:
                        output.append(u"\t\t\t{0!s}: {1!s}".format(error, backend_info[backend_group][backend].errors[error]))

        return output


class BackendInfo(object):

    __backends = collections.defaultdict(dict)
    __last_access = collections.defaultdict(None)

    @classmethod
    def get(cls, group, name):
        """
        Get or create new backend
        :param group: int
        :param name: str
        :return: BackendInfo
        """
        if group in cls.__backends and name in cls.__backends[group]:
            return cls.__backends[group][name]
        else:
            return BackendInfo(group, name)

    @classmethod
    def get_last(cls, group):
        """
        Get last backend was accessed in group
        :param group: int
        :return: BackendInfo
        """
        return cls.__last_access[group]

    @classmethod
    def get_all(cls):
        """
        Get all backends
        :return: dict
        """
        return cls.__backends

    def __init__(self, group, name):
        """
        When creating object - store reference to __backends for faster searching
        :param group: int
        :param name: str
        """
        self.group = group
        self.name = name

        self.connects = 0
        self.requests = 0
        self.successful = 0
        self.errors = collections.defaultdict(int)

        self.request_pending = False
        self.healthy = True

        BackendInfo.__backends[group].update({name: self})

    def count_connect(self):
        """
        On counting connection - reset health status
        """
        self.connects += 1
        self.request_pending = True
        self.healthy = True
        BackendInfo.__last_access.update({self.group: self})

    def count_request(self):
        self.requests += 1

    def count_success(self):
        """
        On success communication - mark backend as healthy
        """
        self.request_pending = False
        self.healthy = True
        self.successful += 1

    def count_error(self, err):
        """
        On error - save it and mark backend as faulty
        :param err: str
        """
        self.request_pending = False
        self.healthy = False
        self.errors[err] += 1

    @property
    def was_success(self):
        """
        Backend communication was not success in two cases:
        - backend returned error
        - backend didn't respond at all
        Looks like both should be triggered as fault
        :return: bool
        """
        return self.healthy and not self.request_pending


class FrontendJobInfo(object):

    def __init__(self, job_id, start_time):
        self.id = job_id
        self.start_time = start_time
        self.start_merge_time = 0
        self.start_send_result_time = 0
        self.finish_time = 0
        self.backend_groups = set()

    def add_backend_group(self, groupid):
        self.backend_groups.add(groupid)


def run():
    ap = argparse.ArgumentParser(description="Simple Log Analyzer")
    ap.add_argument('--debug', action='store_true', help="Enable debug logging and output report to stdout")
    ap.add_argument('--infile', type=str, default='input.txt', metavar='input.txt', help="Input file to analyze")
    ap.add_argument('--outfile', type=str, default='output.txt', metavar='output.txt', help="File to write report")
    args = ap.parse_args()

    logging.basicConfig(level=logging.DEBUG if args.debug else logging.INFO,
                        format='[%(asctime)s.%(msecs)03d] [%(levelname)s] %(message)s',
                        datefmt='%Y:%m:%d %H:%M:%S')
    logging.debug("Starting...")

    sc = StatsCollector()

    try:
        with open(args.infile, mode='r') as infile:
            for line in infile:
                sc.add_log_entry(line)
    except IOError:
        logging.exception('Error reading input file')
        exit(1)

    try:
        with io.open(args.outfile, mode='w', encoding='utf-8') as outfile:
            for line in sc.results:
                outfile.write(line + "\n")
    except IOError:
        logging.exception('Error writing output file')

if __name__ == '__main__':
    run()
