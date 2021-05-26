#!/usr/bin/env python3
import argparse
import os
from Core.BinaryAnalysisCore import BinaryAnalysisCore
from json import dump, dumps


# region Prints
def export_result_file(result_print: dict or list, type_: str, filename: str, tabulaciones: int):
    if type(result_print) == dict:
        if type == "json":
            with open(filename, "w") as f:
                dump(dumps(result_print), f)
        else:
            f = open(filename, "a")
            for i in result_print:
                l = result_print[i]
                if type(l) == dict:
                    f.close()
                    export_result_file(l, type_, filename, tabulaciones + 1)
                    f = open(filename, "a")
                else:
                    [f.write("\t") for i in range(tabulaciones)]
                    f.write(f"{i}: {l}\n")
            f.close()
    else:
        if type == "json":
            with open(filename, "w") as f:
                dump(dumps({"results": result_print}), f)
        else:
            f = open(filename, "a")
            for j in result_print:
                for i in j:
                    l = j[i]
                    if type(l) == dict:
                        f.close()
                        export_result_file(l, type_, filename, tabulaciones + 1)
                        f = open(filename, "a")
                    else:
                        [f.write("\t") for i in range(tabulaciones)]
                        f.write(f"{i}: {l}\n")
                f.write("\n\n")
            f.close()


def export_result(result_print: dict or list, type_: str):
    name: str = "result"
    ext: str = ".txt"
    if type_ == "json":
        ext = ".json"

    if os.path.exists(name+ext) is False:
        export_result_file(result_print, type_, name+ext, 0)
    else:
        for i in range(999):
            if os.path.exists(f"result({i}){ext}") is False:
                export_result_file(result_print, type_, f"{name}({i}){ext}", 0)
                break


def print_tab(tabulaciones: int):
    for i in range(tabulaciones):
        print("\t", end="")


def print_data(result: dict or list, tabulaciones: int):
    if type(result) == dict:
        for i in result:
            l = result[i]
            if type(l) == dict:
                print_data(l, tabulaciones + 1)
            else:
                print_tab(tabulaciones)
                print(f"{i}: {l}")
    else:
        print("\n")
        [print_data(i, 0) for i in result]

# endregion


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Analizador de binarios maliciosos")
    parser.add_argument("-f", "--file", default=None, help="Fichero a escanear")
    parser.add_argument("-d", "--dir", default=None, help="Directorio a escanear")
    parser.add_argument("-c", "--capa", default=False, action="store_true", help="Muestra las capabilities del escaneo")
    parser.add_argument("-s", "--scanners", default="local", help="Scanners a usar(ai_1, virustotal, magic_ext, local, all)")
    parser.add_argument("-r", "--re_scan", default=False, action="store_true", help="Reinicia el scan ignorando el resultado anterior del mismo binario(Si ya existia)")
    parser.add_argument("-o", "--output", default=None, help="Genera un fichero output que contiene el resultado del analisis en (json o plain)")
    parser.add_argument("-n", "--no_save", default=True, action="store_false", help="Fuerza a no guardar los resultados en la base de datos local")
    args = parser.parse_args()

    # region Scanners
    scanners: dict = {
        "ai_1": False,
        "virustotal": False,
        "magic_ext": False,
    }
    # Cambiamos el scanner en concreto a modo true
    if args.scanners in scanners:
        scanners[args.scanners] = True
    # Si se pide todos los scanners o algun grupo
    elif args.scanners == "local" or args.scanners == "all":
        [scanners.update({i: True}) for i in scanners]
        # Quitamos los no locales
        if args.scanners == "local":
            scanners.update({"virustotal": False})

    # print(scanners)
    # endregion
    # region Instanciando ficheros a analizar
    work = None
    # Si se ha seleccionado un archivo, lo llevamos a la variable como string
    if args.file is not None:
        work = args.file
    # Si se ha indicado un dir
    elif args.dir is not None:
        work = [f for f in os.listdir(args.dir) if os.path.isfile(os.path.join(args.dir, f))]
    else:
        print(parser.print_help())
        exit(0)
    # endregion
    # region Lanzando analizador
    b = BinaryAnalysisCore()
    result = None

    if type(work) == list:
        result = [b.run_analysis(f"{args.dir}/{i}", scanners["virustotal"], scanners["ai_1"], scanners["magic_ext"], args.no_save,
                                 args.re_scan) for i in work]
    else:
        result = b.run_analysis(work, scanners["virustotal"], scanners["ai_1"], scanners["magic_ext"], args.no_save,
                                args.re_scan)

    if args.output is None:
        print_data(result, 0)
    elif args.output is not None:
        export_result(result, args.output)

    if args.capa is True:
        if type(work) == list:
            v = input("Se ha introducido un directorio a analizar con capa, ¿Estas seguro que quieres continuar?(y/n)")
            if type(v) == str:
                v = v.lower()
                if v == "y":
                    result = [b.scan_capa(i) for i in work]
                else:
                    print("Saliendo...")
            else:
                print("Saliendo...")
        else:
            result = b.scan_capa(work)

    if args.no_save:
        b.save()
    # endregion
