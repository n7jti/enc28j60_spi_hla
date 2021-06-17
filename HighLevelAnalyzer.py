# High Level Analyzer
# For more information and documentation, please go to https://support.saleae.com/extensions/high-level-analyzer-extensions

from saleae.analyzers import HighLevelAnalyzer, AnalyzerFrame, StringSetting, NumberSetting, ChoicesSetting
from enum import Enum, auto

class States(Enum):
    OPCODE = auto()
    ARGUMENT = auto()
    DATA = auto()
    DISABLE = auto()




# High level analyzers must subclass the HighLevelAnalyzer class.
class Hla(HighLevelAnalyzer):
    # List of settings that a user can set for this High Level Analyzer.
    my_string_setting = StringSetting()
    my_number_setting = NumberSetting(min_value=0, max_value=100)
    my_choices_setting = ChoicesSetting(['A', 'B'])

    # An optional list of types this analyzer produces, providing a way to customize the way frames are displayed in Logic 2.
    result_types = {
        'RCR': {'format': 'RCR {{data.arg}}'},
        'RBM': {'format': 'RBM'},
        'WCR': {'format': 'WCR {{data.arg}}'},
        'WBM': {'format': 'WBM'},
        'BFS': {'format': 'BFS {{data.arg}}'},
        'BFC': {'format': 'BFC {{data.arg}}'},
        'SRC': {'format': 'SRC'},
        'ARG': {'format': 'Arg: {{data.arg}}'}
    }

    def __init__(self):
        '''
        Initialize HLA.

        Settings can be accessed using the same name used above.
        '''
        print("Settings:", self.my_string_setting,
              self.my_number_setting, self.my_choices_setting)

        self.__state = States.DISABLE
        self.__byte0 = bytearray()
        self.__byte1 = bytearray()
        self.__data = bytearray()
        self.__opcode = bytearray()
        self.__argument = bytearray()

    def decode(self, frame: AnalyzerFrame):
        '''
        Process a frame from the input analyzer, and optionally return a single `AnalyzerFrame` or a list of `AnalyzerFrame`s.

        The type and data values in `frame` will depend on the input analyzer.
        '''

        if frame.type == 'enable':
            self.__state = States.OPCODE
            return

        if frame.type == 'disable':
            self.__state = States.DISABLE
            return

        if self.__state == States.OPCODE:
            if frame.type == 'result':
                self.__byte0 = frame.data["mosi"]
                self.__state = States.ARGUMENT
                self.__opcode = (self.__byte0[0]  & 0xE0) >> 5
                self.__argument = self.__byte0[0] & 0x1F
                if self.__opcode == 0b000:
                    return AnalyzerFrame('RCR', frame.start_time, frame.end_time, {'arg': hex(self.__argument)})
                if self.__opcode == 0b001:                 
                    return AnalyzerFrame('RBM', frame.start_time, frame.end_time)
                if self.__opcode == 0b010:
                    return AnalyzerFrame('WCR', frame.start_time, frame.end_time, {'arg': hex(self.__argument)})
                if self.__opcode == 0b011:
                    return AnalyzerFrame('WBM', frame.start_time, frame.end_time)
                if self.__opcode == 0b100:
                    return AnalyzerFrame('BFS', frame.start_time, frame.end_time, {'arg': hex(self.__argument)})
                if self.__opcode == 0b101:
                    return AnalyzerFrame('BFC', frame.start_time, frame.end_time, {'arg': hex(self.__argument)})
                if self.__opcode == 0b111:
                    return AnalyzerFrame('SRC', frame.start_time, frame.end_time)
               

        return
 
