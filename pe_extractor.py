import numpy as np
from sklearn.feature_extraction import FeatureHasher

class FeatureType(object):
    def __init__(self):
        self.name = ''
        self.dim = 0
    def process_raw_features(self, raw_obj):
        raise NotImplementedError

class ByteHistogram(FeatureType):
    def __init__(self):
        self.name = 'histogram'
        self.dim = 256
    def process_raw_features(self, raw_obj):
        counts = np.array(raw_obj, dtype=np.float32)
        return counts / counts.sum() if counts.sum() > 0 else counts

class ByteEntropyHistogram(FeatureType):
    def __init__(self):
        self.name = 'byteentropy'
        self.dim = 256
    def process_raw_features(self, raw_obj):
        counts = np.array(raw_obj, dtype=np.float32)
        return counts / counts.sum() if counts.sum() > 0 else counts

class SectionInfo(FeatureType):
    def __init__(self):
        self.name = 'section'
        self.dim = 5 + 50 + 50 + 50 + 50 + 50
    def process_raw_features(self, raw_obj):
        sections = raw_obj['sections']
        general = [
            len(sections),
            sum(1 for s in sections if s['size'] == 0),
            sum(1 for s in sections if s['name'] == ""),
            sum(1 for s in sections if 'MEM_READ' in s['props'] and 'MEM_EXECUTE' in s['props']),
            sum(1 for s in sections if 'MEM_WRITE' in s['props'])
        ]
        section_sizes = FeatureHasher(50, input_type="pair").transform([[(s['name'], s['size']) for s in sections]]).toarray()[0]
        section_entropy = FeatureHasher(50, input_type="pair").transform([[(s['name'], s['entropy']) for s in sections]]).toarray()[0]
        section_vsize = FeatureHasher(50, input_type="pair").transform([[(s['name'], s['vsize']) for s in sections]]).toarray()[0]
        entry_name = FeatureHasher(50, input_type="string").transform([[raw_obj['entry']]]).toarray()[0]
        characteristics = [p for s in sections for p in s['props'] if s['name'] == raw_obj['entry']]
        char_hashed = FeatureHasher(50, input_type="string").transform([characteristics]).toarray()[0]
        return np.hstack([general, section_sizes, section_entropy, section_vsize, entry_name, char_hashed]).astype(np.float32)

class ImportsInfo(FeatureType):
    def __init__(self):
        self.name = 'imports'
        self.dim = 1280
    def process_raw_features(self, raw_obj):
        libraries = list(set([l.lower() for l in raw_obj.keys()]))
        libraries_hashed = FeatureHasher(256, input_type="string").transform([libraries]).toarray()[0]
        imports = [lib.lower() + ':' + e for lib, elist in raw_obj.items() for e in elist]
        imports_hashed = FeatureHasher(1024, input_type="string").transform([imports]).toarray()[0]
        return np.hstack([libraries_hashed, imports_hashed]).astype(np.float32)

class ExportsInfo(FeatureType):
    def __init__(self):
        self.name = 'exports'
        self.dim = 128
    def process_raw_features(self, raw_obj):
        return FeatureHasher(128, input_type="string").transform([raw_obj]).toarray()[0].astype(np.float32)

class GeneralFileInfo(FeatureType):
    def __init__(self):
        self.name = 'general'
        self.dim = 10
    def process_raw_features(self, raw_obj):
        return np.asarray([raw_obj[k] for k in ['size', 'vsize', 'has_debug', 'exports', 'imports', 'has_relocations', 'has_resources', 'has_signature', 'has_tls', 'symbols']], dtype=np.float32)

class HeaderFileInfo(FeatureType):
    def __init__(self):
        self.name = 'header'
        self.dim = 62
    def process_raw_features(self, raw_obj):
        timestamp = raw_obj['coff']['timestamp']
        machine = FeatureHasher(10, input_type="string").transform([[raw_obj['coff']['machine']]]).toarray()[0]
        characteristics = FeatureHasher(10, input_type="string").transform([raw_obj['coff']['characteristics']]).toarray()[0]
        subsystem = FeatureHasher(10, input_type="string").transform([[raw_obj['optional']['subsystem']]]).toarray()[0]
        dll_caps = FeatureHasher(10, input_type="string").transform([raw_obj['optional']['dll_characteristics']]).toarray()[0]
        magic = FeatureHasher(10, input_type="string").transform([[raw_obj['optional']['magic']]]).toarray()[0]
        opt_headers = [raw_obj['optional'][k] for k in ['major_image_version', 'minor_image_version', 'major_linker_version', 'minor_linker_version', 'major_operating_system_version', 'minor_operating_system_version', 'major_subsystem_version', 'minor_subsystem_version', 'sizeof_code', 'sizeof_headers', 'sizeof_heap_commit']]
        return np.hstack([timestamp, machine, characteristics, subsystem, dll_caps, magic, opt_headers]).astype(np.float32)

class StringExtractor(FeatureType):
    def __init__(self):
        self.name = 'strings'
        self.dim = 104
    def process_raw_features(self, raw_obj):
        hist_divisor = float(raw_obj['printables']) if raw_obj['printables'] > 0 else 1.0
        return np.hstack([raw_obj['numstrings'], raw_obj['avlength'], raw_obj['printables'], np.asarray(raw_obj['printabledist']) / hist_divisor, raw_obj['entropy'], raw_obj['paths'], raw_obj['urls'], raw_obj['registry'], raw_obj['MZ']]).astype(np.float32)

class DataDirectories(FeatureType):
    def __init__(self):
        self.name = 'datadirectories'
        self.dim = 30
    def process_raw_features(self, raw_obj):
        features = np.zeros(30, dtype=np.float32)
        for i in range(min(len(raw_obj), 15)):
            features[2 * i] = raw_obj[i]["size"]
            features[2 * i + 1] = raw_obj[i]["virtual_address"]
        return features

class PEFeatureExtractor:
    def __init__(self):
        self.features = [ByteHistogram(), ByteEntropyHistogram(), StringExtractor(), GeneralFileInfo(), HeaderFileInfo(), SectionInfo(), ImportsInfo(), ExportsInfo(), DataDirectories()]
        self.dim = sum([fe.dim for fe in self.features])

    def process_raw_features(self, raw_obj):
        feature_vectors = [fe.process_raw_features(raw_obj[fe.name]) for fe in self.features]
        return np.hstack(feature_vectors).astype(np.float32)