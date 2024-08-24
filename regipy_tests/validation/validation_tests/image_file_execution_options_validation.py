from regipy.plugins.software.image_file_execution_options import (
    ImageFileExecutionOptions,
)
from regipy_tests.validation.validation import ValidationCase


class ImageFileExecutionOptionsValidationCase(ValidationCase):
    plugin = ImageFileExecutionOptions
    test_hive_file_name = "SOFTWARE.xz"
    expected_entries = [
        {
            "name": "AcroRd32.exe",
            "timestamp": "2011-08-28T22:41:26.348786+00:00",
            "DisableExceptionChainValidation": 0,
        },
        {
            "name": "AcroRd32Info.exe",
            "timestamp": "2011-08-28T22:41:26.342926+00:00",
            "DisableExceptionChainValidation": 0,
        },
        {
            "name": "clview.exe",
            "timestamp": "2010-11-10T10:33:42.573040+00:00",
            "DisableExceptionChainValidation": 0,
        },
        {
            "name": "cnfnot32.exe",
            "timestamp": "2010-11-10T10:33:43.369916+00:00",
            "DisableExceptionChainValidation": 0,
        },
        {
            "name": "DllNXOptions",
            "timestamp": "2009-07-14T04:41:12.790008+00:00",
            "mscoree.dll": 1,
            "mscorwks.dll": 1,
            "mso.dll": 1,
            "msjava.dll": 1,
            "msci_uno.dll": 1,
            "jvm.dll": 1,
            "jvm_g.dll": 1,
            "javai.dll": 1,
            "vb40032.dll": 1,
            "vbe6.dll": 1,
            "ums.dll": 1,
            "main123w.dll": 1,
            "udtapi.dll": 1,
            "mscorsvr.dll": 1,
            "eMigrationmmc.dll": 1,
            "eProcedureMMC.dll": 1,
            "eQueryMMC.dll": 1,
            "EncryptPatchVer.dll": 1,
            "Cleanup.dll": 1,
            "divx.dll": 1,
            "divxdec.ax": 1,
            "fullsoft.dll": 1,
            "NSWSTE.dll": 1,
            "ASSTE.dll": 1,
            "NPMLIC.dll": 1,
            "PMSTE.dll": 1,
            "AVSTE.dll": 1,
            "NAVOPTRF.dll": 1,
            "DRMINST.dll": 1,
            "TFDTCTT8.dll": 1,
            "DJSMAR00.dll": 1,
            "xlmlEN.dll": 1,
            "ISSTE.dll": 1,
            "symlcnet.dll": 1,
            "ppw32hlp.dll": 1,
            "Apitrap.dll": 1,
            "Vegas60k.dll": 1,
        },
        {
            "name": "dw20.exe",
            "timestamp": "2010-11-10T10:33:42.619916+00:00",
            "DisableExceptionChainValidation": 0,
        },
        {
            "name": "dwtrig20.exe",
            "timestamp": "2010-11-10T10:33:42.619916+00:00",
            "DisableExceptionChainValidation": 0,
        },
        {
            "name": "excel.exe",
            "timestamp": "2010-11-10T10:33:43.135540+00:00",
            "DisableExceptionChainValidation": 0,
        },
    ]
    expected_entries_count = 32
