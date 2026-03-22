from setuptools import setup, find_packages

setup(
    name="themeguard",
    version="1.0.0",
    description="WordPress Nulled Theme & Plugin Backdoor Detector",
    author="Muhammad Abid",
    author_email="v3n0msh3ll@proton.me",
    url="https://github.com/V3n0mSh3ll/themeguard",
    packages=find_packages(),
    python_requires=">=3.8",
    install_requires=["colorama>=0.4.6"],
    entry_points={
        "console_scripts": ["themeguard=themeguard:main"],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "Topic :: Security",
        "License :: OSI Approved :: MIT License",
    ],
)
