import threading
import time
from BluHawk.utils import log_exception

class AsyncDataProcessing:
    def __init__(self, model, field, fun, timeout):
        self.model = model
        self.field = field
        self.status = ['processing', 'completed']
        self.active_threads = dict({})
        self.thread_status = dict({})
        self.thread_start_time = dict({})
        self.fun = fun
        self.thread_timeout = timeout
        self.responses = {
            'success': {
                'message': 'Data processing successful',
                'status': 'completed'
            },
            'processing': {
                'message': 'Data processing in progress',
                'status': 'processing'
            },
            'error': {
                'message': 'Data processing failed',
                'status': 'failed'
            },
            'timeout': {
                'message': 'Data processing timed out',
                'status': 'timed_out'
            }
        }

    def handle(self, query: str = None, additional_data: dict = {}):
        try:
            results = self.fetch_data(query, additional_data)
            if not results:
                return self.process_data(query, additional_data)
            response = self.responses.get('success')
            response['data'] = list(results.values())[0]
            self.cleanup_thread(query)
            return response
        except Exception as e:
            log_exception(e)
            self.cleanup_thread(query)
            response = self.responses.get('error')
            response['message'] = str(e)
            return response

    def process_data(self, query, additional_data):
        if self.is_thread_timed_out(query) and not self.active_threads.get(query).is_alive():
            self.cleanup_thread(query)
            
        if self.thread_status.get(query) == self.status[0]:
            return self.responses.get('processing')

        thread = threading.Thread(target=self.save_data, args=( query,additional_data))
        thread.start()
        self.thread_status[query] = self.status[0]
        self.active_threads[query] = thread
        self.thread_start_time[query] = time.time()
        return self.responses.get('processing')

    def fetch_data(self,  query, additional_data):        
        if not query:
            return {'error': 'Query not provided'}

        filter_kwargs = {self.field: query}
        results = self.model.objects.filter(**filter_kwargs)
        return results

    def is_thread_timed_out(self, query):
        if query in self.thread_start_time:
            elapsed_time = time.time() - self.thread_start_time[query]
            return elapsed_time > self.thread_timeout
        return False

    def cleanup_thread(self, query):
        if query in self.active_threads:
            thread = self.active_threads[query]
            if thread.is_alive():
                thread.join(timeout=0)
            self.active_threads.pop(query, None)
            self.thread_status.pop(query, None)
            self.thread_start_time.pop(query, None)

    def save_data(self, query, additional_data):
        pass