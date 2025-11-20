# fixed_port_scanner.py
import socket
import concurrent.futures
from kivy.app import App
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.gridlayout import GridLayout
from kivy.uix.label import Label
from kivy.uix.textinput import TextInput
from kivy.uix.button import Button
from kivy.uix.progressbar import ProgressBar
from kivy.uix.recycleview import RecycleView
from kivy.clock import Clock
from kivy.metrics import dp
from kivy.uix.popup import Popup
from kivy.core.window import Window

Window.clearcolor = (0.1, 0.1, 0.15, 1)

class ResultView(RecycleView):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.viewclass = 'Label'
        self.data = []
        self.size_hint_y = None
        self.height = dp(250)
        self.scroll_type = ['bars', 'content']

    def add_line(self, text, color=(1, 1, 1, 1)):
        self.data.append({
            'text': text,
            'color': color,
            'font_size': '16sp',
            'bold': True
        })
        self.refresh_from_data()

    def clear(self):
        self.data = []
        self.refresh_from_data()


class ScannerLayout(BoxLayout):
    def __init__(self, **kwargs):
        super().__init__(orientation='vertical', padding=dp(12), spacing=dp(12), **kwargs)

        title = Label(text='🔍 Fast Port Scanner', font_size='22sp', bold=True, color=(0.3, 0.8, 1, 1), size_hint_y=None, height=dp(40))
        self.add_widget(title)

        inputs = GridLayout(cols=2, spacing=dp(8), size_hint_y=None, height=dp(120))
        inputs.add_widget(Label(text='IP address:', color=(1, 1, 1, 1)))
        self.ip_input = TextInput(text='127.0.0.1', multiline=False, background_color=(0.2, 0.2, 0.3, 1))
        inputs.add_widget(self.ip_input)

        inputs.add_widget(Label(text='Start port:', color=(1, 1, 1, 1)))
        self.start_port_input = TextInput(text='1', multiline=False, background_color=(0.2, 0.2, 0.3, 1))
        inputs.add_widget(self.start_port_input)

        inputs.add_widget(Label(text='End port:', color=(1, 1, 1, 1)))
        self.end_port_input = TextInput(text='1024', multiline=False, background_color=(0.2, 0.2, 0.3, 1))
        inputs.add_widget(self.end_port_input)

        self.add_widget(inputs)

        self.scan_btn = Button(text='🚀 Scan', background_color=(0.2, 0.6, 0.2, 1), font_size='18sp', size_hint_y=None, height=dp(50))
        self.add_widget(self.scan_btn)

        self.progress = ProgressBar(max=100, value=0, size_hint_y=None, height=dp(20))
        self.status_label = Label(text='Idle', size_hint_y=None, height=dp(26), color=(1, 1, 0.5, 1))
        self.add_widget(self.progress)
        self.add_widget(self.status_label)

        self.result_view = ResultView()
        self.add_widget(self.result_view)

        self.scan_btn.bind(on_release=self.on_scan)

    def on_scan(self, *_):
        ip = self.ip_input.text.strip()

        try:
            socket.inet_aton(ip)
        except OSError:
            self.set_status('Invalid IP')
            return

        try:
            start_port = int(self.start_port_input.text)
            end_port = int(self.end_port_input.text)
        except ValueError:
            self.set_status('Invalid port range')
            return

        if start_port > end_port:
            self.set_status('Start port cannot exceed end port')
            return

        self.result_view.clear()
        self.progress.value = 0
        self.progress.max = max(1, end_port - start_port + 1)
        self.set_status(f'Scanning {ip}...')

        executor = concurrent.futures.ThreadPoolExecutor(max_workers=100)
        futures = [executor.submit(self.check_port, ip, port, 0.1) for port in range(start_port, end_port + 1)]

        open_ports = []
        processed_ports = set()

        def collect_results(dt):
            for f in futures:
                if f.done():
                    port, is_open = f.result()
                    if port not in processed_ports:
                        processed_ports.add(port)
                        if is_open:
                            open_ports.append(port)
                            self.result_view.add_line(f'✅ Port {port} is OPEN', color=(0.2, 1, 0.2, 1))

            self.progress.value = len(processed_ports)

            if len(processed_ports) == len(futures):
                if open_ports:
                    summary = f'Open ports ({len(open_ports)}): {open_ports}'
                else:
                    summary = 'No open ports found'

                self.set_status(summary)
                self.show_popup(summary)
                Clock.unschedule(collect_results)

        Clock.schedule_interval(collect_results, 0.1)

    def set_status(self, text):
        self.status_label.text = text

    def show_popup(self, message):
        popup = Popup(title='📊 Scan Summary', content=Label(text=message, color=(1, 1, 1, 1)), size_hint=(0.7, 0.4), background_color=(0.1, 0.3, 0.5, 1))
        popup.open()

    @staticmethod
    def check_port(ip, port, timeout=0.1):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(timeout)
                result = sock.connect_ex((ip, port))
                return port, (result == 0)
        except Exception:
            return port, False

class FinalPortScannerApp(App):
    def build(self):
        return ScannerLayout()

if __name__ == '__main__':
    FinalPortScannerApp().run()
