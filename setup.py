import setuptools

with open("README.md", "r", encoding="utf-8") as f:
	description = f.read()

setuptools.setup(
	name="manghidra",
	version="0.1",
	package_dir={"":"src"},
	include_package_data = True,
	packages=setuptools.find_packages(where="src"),
	python_requires=">=3.8")