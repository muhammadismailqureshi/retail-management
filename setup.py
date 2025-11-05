from setuptools import setup, find_packages

with open('README.md', 'r', encoding='utf-8') as f:
    long_description = f.read()

setup(
    name='retail-management-system',
    version='1.0.0',
    author='Almayas Retail',
    description='A comprehensive retail management solution',
    long_description=long_description,
    long_description_content_type='text/markdown',
    url='https://github.com/yourusername/retail-management-system',
    packages=find_packages(),
    include_package_data=True,
    install_requires=[
        'bcrypt>=3.2.0',
        'pillow>=9.0.0',
        'matplotlib>=3.5.0',
        'reportlab>=3.6.0',
        'pandas>=1.3.0',
        'numpy>=1.21.0',
    ],
    python_requires='>=3.8',
    entry_points={
        'console_scripts': [
            'retail-system=retail_management_system.__main__:main',
        ],
    },
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Intended Audience :: End Users/Desktop',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Operating System :: OS Independent',
    ],
)
