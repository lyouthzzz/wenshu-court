# -*- coding: utf-8 -*
from crawler.downloader import Downloader
from crawler.pipeline import Pipeline
from crawler.processor import Processor
from crawler.schedule import Schedule
from crawler.request import Request

import time

class Spider():

    def __init__(self):
        self.downloader = Downloader()
        self.processor = Processor()
        self.pipeline = Pipeline()
        self.schedule = Schedule()
    
    def set_downloader(self, downloader):
        self.downloader = downloader

    def set_processor(self, processor):
        self.processor = processor
    
    def set_pipeline(self, pipeline):
        self.pipeline = pipeline
    
    def set_schedule(self, schedule):
        self.schedule = schedule

    def run(self):
        while(True):
            request = self.schedule.pop()
            if request is None:
                print('等待 5 秒')
                time.sleep(5)
                continue
            print('pop url :' + request.url)
            page = self.downloader.download(request)
            if(not page.download_success()):
                self.schedule.push(request)
                continue
            self.processor.process(page)
            self.add_target_url(page)
            if (page.is_skip):
                continue
            # 持久化
            self.pipeline.data_persistent(page.get_item())
            print('等待 5 秒')
            time.sleep(5)


    def add_target_url(self, page):
        for request in page.get_target_requests():
            self.schedule.push(request)
            print('add target url : ' + request.url)

    def add_start_url(self, request):
        if (isinstance(request , Request)):
            self.schedule.push(request)
        elif(isinstance(request, str)):
            self.schedule.push(Request(request))


if __name__ == "__main__":
    spider = Spider()
    spider.add_start_url('http://wenshu.court.gov.cn/List/List?sorttype=1&conditions=searchWord+1++%E6%B0%91%E4%BA%8B%E6%A1%88%E4%BB%B6+%E6%A1%88%E4%BB%B6%E7%B1%BB%E5%9E%8B:%E6%B0%91%E4%BA%8B%E6%A1%88%E4%BB%B6')
    # spider.add_start_url('http://wenshu.court.gov.cn/content/content?DocID=465f975a-e473-4b23-887a-61b05f9341b4')
    spider.run()