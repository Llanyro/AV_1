import numpy
import os
import pickle
import re
from enum import Enum
from matplotlib import pyplot
from sklearn import metrics
from sklearn.feature_extraction import FeatureHasher
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import KFold


class TrainJob(Enum):
    Save = 0
    Get = 1


class AIScan:
    __ai_name: str                                  # Nombre que recibira esta ia
    __model_filename: str                           # Fichero donde guardar y leer los datos
    __hasher: FeatureHasher = FeatureHasher(20000)  #

    def __init__(self, ai_name: str, model_filename: str = None):
        self.__ai_name = ai_name
        if model_filename is None:
            self.__model_filename = f"Core/{self.__ai_name}.sav"
        else:
            self.__model_filename = model_filename

    def scan_file(self, filename: str) -> float:
        """
        Escaneamos fichero y devolvemos si e malicioso o no, en una escala de 0-1(menos a mas malicioso)
        Devuelve -1 si no hay dataset de entrenamiento
        """
        if not os.path.exists(self.__model_filename):
            return -1
        with open(self.__model_filename, "rb") as saved_detector:
            classifier = pickle.load(saved_detector)
        features = self.__get_string_features(filename)
        result_proba = classifier.predict_proba([features])[:, 1]
        # if the user specifies malware_paths and benignware_paths, train a detector
        return result_proba

    def __get_string_features(self, path: str) -> numpy.ndarray:
        # No es necesario que analiceis esta funcion profundamente
        chars = r" -~"
        min_length = 5
        string_regexp = '[%s]{%d,}' % (chars, min_length)
        with open(path, "rb") as f:
            data: bytes = f.read()
            pattern = re.compile(string_regexp.encode("utf8"))
            strings: list = pattern.findall(data)

            string_features: dict = {}
            [string_features.update({i: 1}) for i in strings]

            hashed_features = self.__hasher.transform([string_features])
            hashed_features = hashed_features.todense()
            hashed_features = numpy.asarray(hashed_features)
            hashed_features = hashed_features[0]
            # print("Extracted {0} strings from {1}".format(string_features.__len__(), path))
        return hashed_features

    def __get_training_paths(self, directory: str) -> list:
        return [os.path.join(directory, i) for i in os.listdir(directory)]

    def train(self, benign_path: str, malicious_path: str, job: TrainJob = TrainJob.Get) -> (list, list):
        """
        Entrena un dataset segun binarios malignos y buenignos
        Y lo devuelve o guarda si se solicita
        """
        # Lista de paths buenware y malware
        malicious_paths: list = self.__get_training_paths(malicious_path)
        benign_paths: list = self.__get_training_paths(benign_path)

        X: list = [self.__get_string_features(path) for path in malicious_paths + benign_paths]
        y: list = [1 for i in range(malicious_paths.__len__())] + [0 for i in range(benign_paths.__len__())]

        if job == TrainJob.Save:
            classifier = LogisticRegression()
            classifier.fit(X, y)
            with open(self.__model_filename, "wb") as f:
                pickle.dump(classifier, f)
        return X, y

    def cv_evaluate(self, X: list, y: list) -> None:
        X_array = numpy.array(X)
        y_array = numpy.array(y)
        fold_counter = 0
        for i, test in KFold(2, shuffle=True).split(X):
            training_X, training_y = X_array[i], y_array[i]
            test_X, test_y = X_array[test], y_array[test]

            classifier = LogisticRegression()
            classifier.fit(training_X, training_y)
            scores = classifier.predict_proba(test_X)[:, -1]
            fpr, tpr, thresholds = metrics.roc_curve(test_y, scores)
            pyplot.semilogx(fpr, tpr, label="ROC curve".format(fold_counter))
            fold_counter += 1
            break
        pyplot.xlabel("Tasa falsos positivos")
        pyplot.ylabel("Tasa de veraderos postivos")
        pyplot.title("Curva ROC")
        pyplot.legend()
        pyplot.grid()
        pyplot.show()

