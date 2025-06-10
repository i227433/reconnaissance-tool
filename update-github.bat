@echo off
echo Updating GitHub repository...
git add .
git status
set /p message="Enter commit message: "
git commit -m "%message%"
git push origin master
echo.
echo Repository updated successfully!
pause
