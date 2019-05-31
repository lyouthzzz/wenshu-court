from crawler.request import Request
class Page():
    def __init__(self):
        self.request = None
        self.status_code = None
        self.success = False
        self.is_skip = True
        self.text = None
        self.item = {}
        self.target_requests = []

    @staticmethod
    def mapping(response):
        page = Page()
        page.request = Request(response.url)
        page.status_code = response.status_code
        page.text = response.text
        return page

    @staticmethod
    def failed():
        return Page()

    def add_request(self, request):
        self.target_requests.append(request)

    def get_target_requests(self):
        return self.target_requests

    def put_field(self, key, value):
        self.item[key] = value

    def get_item(self):
        return self.item

    def set_skip(self, is_skip):
        self.is_skip = is_skip
    
    def download_success(self):
        return self.success

    def set_success(self, suc):
        self.success = suc

    def set_url(self, url):
        self.request.set_url(url)