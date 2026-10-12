import * as fs from 'fs';
import * as path from 'path';

export function isDirectory(filePath: string): boolean {
  try {
    const stats = fs.statSync(filePath);
    return stats.isDirectory();
  } catch {
    return false;
  }
}

export function getAllFiles(dirPath: string, fileList: string[] = []): string[] {
  if (!fs.existsSync(dirPath)) {
    return fileList;
  }
  
  const files = fs.readdirSync(dirPath);
  
  for (const file of files) {
    const filePath = path.join(dirPath, file);
    
    try {
      const stats = fs.statSync(filePath);
      
      if (stats.isDirectory()) {
        if (file === 'node_modules' || file === '.git' || file === 'dist' || file === 'build') {
          continue;
        }
        getAllFiles(filePath, fileList);
      } else {
        fileList.push(filePath);
      }
    } catch {
      continue;
    }
  }
  
  return fileList;
}

export function getDirectoryCount(dirPath: string): number {
  let count = 0;
  
  if (!fs.existsSync(dirPath)) {
    return count;
  }
  
  const files = fs.readdirSync(dirPath);
  
  for (const file of files) {
    const filePath = path.join(dirPath, file);
    
    try {
      const stats = fs.statSync(filePath);
      
      if (stats.isDirectory()) {
        if (file === 'node_modules' || file === '.git') {
          continue;
        }
        count++;
        count += getDirectoryCount(filePath);
      }
    } catch {
      continue;
    }
  }
  
  return count;
}
