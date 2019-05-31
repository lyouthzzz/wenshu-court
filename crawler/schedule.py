from queue import Queue

class Schedule():
    def __init__(self, max_size = 10000):
        self.queue = Queue(max_size)
    
    def pop(self):
        return self.queue.get(timeout=5) if not self.queue.empty() else None

    def push(self, request):
        self.queue.put(request)