from setuptools import Extension
from setuptools import setup, find_packages


module = Extension(
    "BLESMPServer",
    sources=['BLESMPServer.cpp','smp.c', 'util.c', 'ecc.c', 'crypto.c', 'bthost.c'],
    include_dirs=[
            './'
        ],
    extra_compile_args=['-Wall', '-fpermissive'],
    language='c++'
)

setup(
    name="BLESMPServer",
    version="1.0.1",
    description="SMP Server library",
    author="Matheus Eduardo Garbelini",
    author_email="mgarbelix@gmail.com",
    packages=find_packages(),
    license="MIT",
    classifiers=[
        "Programming Language :: Python :: 2",
        "Programming Language :: Python :: 3",
    ],
    ext_modules=[module],
)