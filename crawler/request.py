class Request():
    def __init__(self, url):
        self.url = url
        self.items = {}
    
    def set_url(self, url):
        self.url = url

    def add_item(self, key, val):
        self.items[key] = val

    def add_items(self, items):
        self.items = items

    def get_items(self):
        return self.items