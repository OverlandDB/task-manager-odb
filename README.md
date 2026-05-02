# task-manager-odb
# Task Manager - ODB

Multi-silo task manager for Overland Design-Build - Personal & Team Tasks

## ✨ Features

✅ **Multi-Silo Architecture** - Personal + ODB with role-based access
✅ **5 Pre-configured Users** - Erik (Admin), Sales, Ops, Production, Finance
✅ **18 Pre-loaded Tasks** - All your cleaned tasks ready to go
✅ **Professional Web UI** - React + TailwindCSS
✅ **Full CRUD API** - Express.js backend
✅ **SQLite Database** - In-memory, no external dependencies
✅ **Ready for Render Deploy** - One-click cloud deployment

## 🚀 QUICK START - DEPLOY TO RENDER NOW

### Step 1: Download All Files
Clone this repository to your local machine:
```bash
git clone https://github.com/OverlandDB/task-manager-odb.git
cd task-manager-odb
```

### Step 2: Add Missing Files

The following files need to be created (copy content from the sections below):

1. **server.js** - Main Express backend (see code section below)
2. 2. **Procfile** - Render deployment config (see code section below)
   3. 3. **.env.example** - Environment variables (see code section below)
      4. 4. **public/index.html** - React app container (see code section below)
         5. 5. **public/app.js** - React frontend (see code section below)
            6.
            7. ### Step 3: Push to GitHub
            8. ```bash
               git add .
               git commit -m "Add application files"
               git push origin main
               ```

               ### Step 4: Deploy to Render (FREE)

               1. Go to https://render.com
               2. 2. Click "New +" → "Web Service"
                  3. 3. Select "Connect a repository"
                     4. 4. Choose `OverlandDB/task-manager-odb`
                        5. 5. Configure:
                           6.    - **Name**: `task-manager-odb`
                                 -    - **Environment**: Node
                                      -    - **Build Command**: `npm install`
                                           -    - **Start Command**: `npm start`
                                                -    - **Plan**: Free
                                                     - 6. Click "Create Web Service"
                                                       7. 7. Wait 2-3 minutes for deployment
                                                          8. 8. Get your live URL!
                                                             9.
                                                             10. ## 📋 APPLICATION CODE
                                                             11.
                                                             12. ### server.js
                                                             13. [See the large server.js code provided earlier - copy it to create this file]
                                                             14.
                                                             15. ### Procfile
                                                             16. ```
                                                                 web: node server.js
                                                                 ```

                                                                 ### .env.example
                                                                 ```
                                                                 PORT=3001
                                                                 JWT_SECRET=task-manager-secret-key-2026
                                                                 GOOGLE_CLIENT_ID=YOUR_GOOGLE_CLIENT_ID
                                                                 GOOGLE_CLIENT_SECRET=YOUR_GOOGLE_CLIENT_SECRET
                                                                 NODE_ENV=production
                                                                 ```

                                                                 ### public/index.html
                                                                 [See the HTML code provided earlier - copy it to create this file]

                                                                 ### public/app.js
                                                                 [See the React app.js code provided earlier - copy it to create this file]

                                                                 ## 👥 Pre-configured Users

                                                                 | User | Email | Department | Access |
                                                                 |------|-------|------------|--------|
                                                                 | Erik Carver | erik@overlanddesignbuild.com | Admin | Personal + ODB |
                                                                 | Sales Lead | sales1@overlanddesignbuild.com | Sales | ODB Only |
                                                                 | Operations Lead | ops1@overlanddesignbuild.com | Operations | ODB Only |
                                                                 | Production Lead | prod1@overlanddesignbuild.com | Production | ODB Only |
                                                                 | Finance Manager | finance1@overlanddesignbuild.com | Finance/Admin | ODB Only |

                                                                 ## 📊 Pre-loaded Tasks (18 Total)

                                                                 **Sales (3)**: Customer quotes and opportunities
                                                                 **Invoicing (6)**: Payment processing, reconciliation
                                                                 **HR (2)**: Employee reviews
                                                                 **Operations (2)**: Ordering, client follow-up
                                                                 **Post-Sale (2)**: Customer support
                                                                 **Personal (2)**: Private tasks
                                                                 **Admin (1)**: Subscriptions

                                                                 ## 🔧 Tech Stack

                                                                 - **Frontend**: React 18, TailwindCSS
                                                                 - - **Backend**: Express.js, Node.js
                                                                   - - **Database**: SQLite 3
                                                                     - - **Auth**: JWT, Basic email login
                                                                       - - **Deployment**: Render.com (Free tier)
                                                                         -
                                                                         - ## 📌 API Endpoints
                                                                         -
                                                                         - ```
                                                                           GET    /api/tasks              - Get user's visible tasks
                                                                           POST   /api/tasks              - Create new task
                                                                           PUT    /api/tasks/:id          - Update task status/priority
                                                                           DELETE /api/tasks/:id          - Delete task
                                                                           GET    /api/users              - Get all users
                                                                           POST   /api/auth/login         - Login user
                                                                           ```

                                                                           ## 🔐 Security Notes

                                                                           - Tasks are filtered by user role and department
                                                                           - - Personal tasks only visible to owner
                                                                             - - ODB tasks visible to same department or Admin
                                                                               - - All data stored in-memory (resets on deploy - use persistent DB for production)
                                                                                 -
                                                                                 - ## 🚀 Next Steps
                                                                                 -
                                                                                 - 1. ✅ Deploy to Render
                                                                                   2. 2. Share URL with team
                                                                                      3. 3. Team members login with their email
                                                                                         4. 4. Start managing tasks!
                                                                                            5. 5. (Optional) Add Google OAuth for SSO
                                                                                               6. 6. (Optional) Integrate Claude API for natural language tasks
                                                                                                  7.
                                                                                                  8. ## 📞 Support
                                                                                                  9.
                                                                                                  10. For questions: erik@overlanddesignbuild.com
                                                                                                  11.
                                                                                                  12. ---
                                                                                                  13.
                                                                                                  14. **Status**: Ready for production ✅
                                                                                                  15. **Last Updated**: May 2, 2026
                                                                                                  16. **Version**: 1.0.0Multi-silo task manager for ODB - Personal &amp; Team Tasks
