import * as fs from 'fs';
import * as path from 'path';

export const SKIP_DIRS = new Set([
  'node_modules', '.git', 'dist', 'build', '.venv', 'venv', '__pycache__', 'target',
  'Pods', '.next', '.cache', 'vendor', '.dart_tool', '.gradle', 'DerivedData'
]);
export const MAX_FILE_BYTES = 1024 * 1024;

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
        if (SKIP_DIRS.has(file)) {
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
        if (SKIP_DIRS.has(file)) {
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

export interface FileSizeWarning {
  actualSize: number;
  truncated: boolean;
}

export function checkFileSize(filePath: string): FileSizeWarning | null {
  try {
    const stats = fs.statSync(filePath);
    if (stats.size > MAX_FILE_BYTES) {
      return { actualSize: stats.size, truncated: true };
    }
  } catch {
    // Ignore stat errors
  }
  return null;
}
