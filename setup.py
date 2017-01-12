from setuptools import setup

package_name = "YahooSports"
install_requires = ['rauth==0.7.2','requests==2.12.4']
setup(
    name=package_name,
    packages=[package_name],
    install_requires=install_requires,
    version=open(package_name + "/__version__.py").readlines()[-1].split()[-1].strip("\"'"),
    description='Yahoo Sports API',
    author='Jason Bell',
    author_email='jbellthor@gmail.com',
    scripts=[],
)

