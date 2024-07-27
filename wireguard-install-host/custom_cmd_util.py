#!/usr/bin/env python3
import subprocess
import shlex
import os
import pwd
import grp
import shutil

class RunCommandContainer: 
   def __init__(self, command, suppress_output = False):
      """
      std_out and std_err are guaranteed to be strings
      """
      self.command = command
      self.std_out = ""
      self.std_out_formatted = ""
      self.std_err = ""
      self.std_err_formatted = ""
      self.return_code = 0
      
      #region RUN
      command_tokens = shlex.split(command.replace("\n", " ").replace("\t", " ").strip())
      print(f"RUNCMD: \"{command}\"")
      t = subprocess.run(command_tokens, 
         check = False,
         stdout = subprocess.PIPE,
         stderr = subprocess.PIPE,
         universal_newlines = True)
      
      self.return_code = t.returncode
      self.std_out = str(t.stdout).strip()
      self.std_out_formatted = '\n'.join( [f"   [std::out] > {s}" for s in self.std_out.split("\n")] )
      self.std_err = str(t.stderr).strip()
      self.std_err_formatted = '\n'.join( [f"   [std::err] > {s}" for s in self.std_err.split("\n")] )
      
      print(f"Command finished:")
      print(f"   CMD: (RET {self.return_code}) {self.command}")
      if len(self.std_out) > 0:
         print(self.std_out_formatted)
      if len(self.std_err) > 0:
         print(self.std_err_formatted)
      #endregion
   
   def Check(self):
      """
      Returns self
      """
      if self.return_code != 0:
         raise Exception(f"Exit code not 0: {self.return_code}")
      return self


def chk_usr_exists(usr_name: str) -> bool:
   try:
      pwd.getpwnam(usr_name)
      return True
   except KeyError:
      return False
   
def chk_grp_exists(grp_name: str) -> bool:
   try:
      grp.getgrnam(grp_name)
      return True
   except KeyError:
      return False

def file_read(path: str) -> str:
   """
   Reads the file using the open() function
   """
   if not os.path.exists(path):
      raise Exception(f"File not found: \"{path}\"")
   with open(path, "r") as f:
      return f.read()
   
def file_write(path: str, contents: str, permission_bits: int | None = None):
   """
   Writes the given contents to the file, overrides the file contents
   Writes the data as utf-8
   """
   if os.path.exists(path):
      if not os.path.isfile(path):
         raise Exception(f"Not a file: {path}")
      with open(path, "r+", encoding="utf-8") as f:
         f.seek(0)
         f.write(contents)
         f.truncate()
   else:
      with open(path, "w", encoding="utf-8") as f:
         f.write(contents)
   if isinstance(permission_bits, int):
      print(f"<{oct(permission_bits)}> \"{path}\"")
      os.chmod(path, permission_bits)
      
def clear_directory(directory):
   """
   Removes all contents of a directory.
   Use carefully
   """
   if not os.path.isdir(directory):
      raise Exception(f"Not a directory: \"{directory}\"")
   
   for filename in os.listdir(directory):
      file_path = os.path.join(directory, filename)
      try:
         if os.path.isfile(file_path) or os.path.islink(file_path):
            os.unlink(file_path)
         elif os.path.isdir(file_path):
            shutil.rmtree(file_path)
      except Exception as e:
         print(f'Failed to delete {file_path}. Reason: {e}')
