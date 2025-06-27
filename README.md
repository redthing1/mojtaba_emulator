# Emulator-Debugger Hybrid 🐉🛠️


*A unique hybrid tool combining debugger and emulator for precise execution and deep logging of complex programs*

---

## Overview

This project is a unique hybrid tool between a **debugger** and an **emulator**, designed for precise execution of complex applications, especially those protected with layers like DRM in games.

The program runs the target application using debugging features and executes the main parts of the code with **Unicorn Engine**. When execution reaches Windows API functions, it sets a **breakpoint** on their return addresses and hands control back to Unicorn. This results in **highly accurate and detailed logs**.

---

## What Makes This Project Unique?

- Hybrid execution combining debugger and emulator for high precision and performance  
- Detailed logging, especially around Windows API function calls  
- Ideal for complex and protected applications (e.g., DRM-protected games)  
- Full control over execution at function and return address levels  

---

## Features

- Executes code segments using **Unicorn Engine** for speed and flexibility  
- Sets **breakpoints** at Windows API return addresses and resumes emulation  
- Produces reliable and detailed logs for in-depth program analysis  
- Designed to handle the complexity of protected software execution  

---

## Usage

```bash
git clone --recurse-submodules https://github.com/mojtabafalleh/emulator.git
cd emulator
# Run the program with your target application
./emulator --target your_program.exe
