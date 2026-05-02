const React = window.React;
const ReactDOM = window.ReactDOM;

const mockUsers = [
  {id:1, name:'Erik Carver', role:'admin', department:'Admin'},
  {id:2, name:'John Sales', role:'user', department:'Sales'},
  {id:3, name:'Jane Ops', role:'user', department:'Operations'},
  {id:4, name:'Mike Prod', role:'user', department:'Production'},
  {id:5, name:'Sarah Finance', role:'user', department:'Finance/Admin'}
  ];

const mockTasks = [
  {id:1, title:'Onboard new sales rep', category:'Sales', priority:'high', dueDate:'2025-05-15', status:'pending', owner:'John Sales'},
  {id:2, title:'Follow up on leads', category:'Sales', priority:'high', dueDate:'2025-05-10', status:'in-progress', owner:'John Sales'},
  {id:3, title:'Generate sales report', category:'Sales', priority:'medium', dueDate:'2025-05-20', status:'pending', owner:'John Sales'},
  {id:4, title:'Process invoice batch', category:'Invoicing', priority:'high', dueDate:'2025-05-05', status:'in-progress', owner:'Erik Carver'},
  {id:5, title:'Reconcile accounts', category:'Invoicing', priority:'high', dueDate:'2025-05-08', status:'pending', owner:'Erik Carver'},
  {id:6, title:'Send payment reminders', category:'Invoicing', priority:'medium', dueDate:'2025-05-12', status:'pending', owner:'Erik Carver'},
  {id:7, title:'Review payroll', category:'Invoicing', priority:'high', dueDate:'2025-05-06', status:'pending', owner:'Sarah Finance'},
  {id:8, title:'File tax documents', category:'Invoicing', priority:'medium', dueDate:'2025-05-30', status:'pending', owner:'Sarah Finance'},
  {id:9, title:'Hire new team member', category:'HR', priority:'high', dueDate:'2025-05-20', status:'pending', owner:'Erik Carver'},
  {id:10, title:'Conduct team review', category:'HR', priority:'medium', dueDate:'2025-05-15', status:'pending', owner:'Erik Carver'},
  {id:11, title:'Schedule safety meeting', category:'Operations', priority:'medium', dueDate:'2025-05-10', status:'pending', owner:'Jane Ops'},
  {id:12, title:'Inventory check', category:'Operations', priority:'high', dueDate:'2025-05-07', status:'in-progress', owner:'Jane Ops'},
  {id:13, title:'Follow up on project delivery', category:'Post-Sale', priority:'high', dueDate:'2025-05-12', status:'pending', owner:'Mike Prod'},
  {id:14, title:'Schedule warranty check', category:'Post-Sale', priority:'medium', dueDate:'2025-05-25', status:'pending', owner:'Mike Prod'},
  {id:15, title:'Update project timeline', category:'Admin', priority:'medium', dueDate:'2025-05-10', status:'pending', owner:'Erik Carver'},
  {id:16, title:'Plan Q3 strategy', category:'Personal', priority:'high', dueDate:'2025-05-15', status:'pending', owner:'Erik Carver'},
  {id:17, title:'Review budget', category:'Personal', priority:'medium', dueDate:'2025-05-20', status:'pending', owner:'Erik Carver'},
  {id:18, title:'Team standup meeting', category:'Operations', priority:'low', dueDate:'2025-05-09', status:'completed', owner:'Jane Ops'}
  ];

function TaskManager() {
    const [tasks, setTasks] = React.useState(mockTasks);
    const [currentUser, setCurrentUser] = React.useState(mockUsers[0]);
    const [filter, setFilter] = React.useState('all');
    const [newTask, setNewTask] = React.useState('');

  const filteredTasks = tasks.filter(task => {
        if(currentUser.role === 'admin') return true;
        if(filter === 'assigned' && task.owner !== currentUser.name) return false;
        if(filter === 'my-dept' && task.category !== currentUser.department && task.category !== 'Admin') return false;
        return true;
  });

  const handleStatusChange = (id, newStatus) => {
        setTasks(tasks.map(t => t.id === id ? {...t, status: newStatus} : t));
  };

  const handleAddTask = () => {
        if(newTask.trim()) {
                setTasks([...tasks, {id: tasks.length+1, title: newTask, category: 'Admin', priority: 'medium', dueDate: new Date().toISOString().split('T')[0], status: 'pending', owner: currentUser.name}]);
                setNewTask('');
        }
  };

  const handleDeleteTask = (id) => {
        setTasks(tasks.filter(t => t.id !== id));
  };

  return React.createElement('div', {className: 'min-h-screen bg-gradient-to-br from-slate-900 to-slate-800 text-white'},
                                 React.createElement('nav', {className: 'bg-slate-800 border-b border-slate-700 px-6 py-4'},
                                                           React.createElement('div', {className: 'flex justify-between items-center'},
                                                                                       React.createElement('h1', {className: 'text-3xl font-bold'}, 'Task Manager - ODB'),
                                                                                       React.createElement('div', {className: 'flex gap-4 items-center'},
                                                                                                                     React.createElement('select', {value: currentUser.id, onChange: (e) => setCurrentUser(mockUsers.find(u => u.id === parseInt(e.target.value))), className: 'bg-slate-700 text-white px-4 py-2 rounded'},
                                                                                                                                                     mockUsers.map(u => React.createElement('option', {key: u.id, value: u.id}, u.name + ' (' + u.department + ')'))
                                                                                                                                                   ),
                                                                                                                     React.createElement('span', {className: 'text-sm text-gray-300'}, currentUser.name)
                                                                                                                   )
                                                                                     )
                                                         ),
                                 React.createElement('div', {className: 'max-w-7xl mx-auto p-6'},
                                                           React.createElement('div', {className: 'bg-slate-700 rounded-lg p-6 mb-6'},
                                                                                       React.createElement('div', {className: 'flex gap-2 mb-4'},
                                                                                                                     React.createElement('button', {onClick: () => setFilter('all'), className: 'px-4 py-2 rounded ' + (filter === 'all' ? 'bg-blue-600' : 'bg-slate-600')}, 'All Tasks'),
                                                                                                                     React.createElement('button', {onClick: () => setFilter('assigned'), className: 'px-4 py-2 rounded ' + (filter === 'assigned' ? 'bg-blue-600' : 'bg-slate-600')}, 'My Tasks'),
                                                                                                                     React.createElement('button', {onClick: () => setFilter('my-dept'), className: 'px-4 py-2 rounded ' + (filter === 'my-dept' ? 'bg-blue-600' : 'bg-slate-600')}, 'My Department')
                                                                                                                   ),
                                                                                       React.createElement('div', {className: 'flex gap-2'},
                                                                                                                     React.createElement('input', {type: 'text', value: newTask, onChange: (e) => setNewTask(e.target.value), placeholder: 'Add new task...', className: 'flex-1 bg-slate-600 text-white px-4 py-2 rounded', onKeyPress: (e) => e.key === 'Enter' && handleAddTask()}),
                                                                                                                     React.createElement('button', {onClick: handleAddTask, className: 'bg-green-600 hover:bg-green-700 px-6 py-2 rounded'}, 'Add Task')
                                                                                                                   )
                                                                                     ),
                                                           React.createElement('div', {className: 'space-y-3'},
                                                                                       filteredTasks.map(task => React.createElement('div', {key: task.id, className: 'bg-slate-700 rounded-lg p-4 border-l-4 ' + (task.status === 'completed' ? 'border-green-500 opacity-60' : task.priority === 'high' ? 'border-red-500' : 'border-yellow-500')},
                                                                                                                                               React.createElement('div', {className: 'flex justify-between items-start'},
                                                                                                                                                                               React.createElement('div', {className: 'flex-1'},
                                                                                                                                                                                                                 React.createElement('h3', {className: 'font-bold text-lg ' + (task.status === 'completed' ? 'line-through' : '')}, task.title),
                                                                                                                                                                                                                 React.createElement('div', {className: 'text-sm text-gray-300 mt-2'},
                                                                                                                                                                                                                                                     React.createElement('span', {className: 'inline-block bg-slate-600 px-2 py-1 rounded mr-2'}, task.category),
                                                                                                                                                                                                                                                     React.createElement('span', {className: 'inline-block bg-slate-600 px-2 py-1 rounded mr-2'}, 'Due: ' + task.dueDate),
                                                                                                                                                                                                                                                     React.createElement('span', {className: 'inline-block bg-slate-600 px-2 py-1 rounded'}, task.owner)
                                                                                                                                                                                                                                                   )
                                                                                                                                                                                                               ),
                                                                                                                                                                               React.createElement('div', {className: 'flex gap-2'},
                                                                                                                                                                                                                 React.createElement('select', {value: task.status, onChange: (e) => handleStatusChange(task.id, e.target.value), className: 'bg-slate-600 text-white px-3 py-1 rounded text-sm'},
                                                                                                                                                                                                                                                     React.createElement('option', {value: 'pending'}, 'Pending'),
                                                                                                                                                                                                                                                     React.createElement('option', {value: 'in-progress'}, 'In Progress'),
                                                                                                                                                                                                                                                     React.createElement('option', {value: 'completed'}, 'Completed')
                                                                                                                                                                                                                                                   ),
                                                                                                                                                                                                                 React.createElement('button', {onClick: () => handleDeleteTask(task.id), className: 'bg-red-600 hover:bg-red-700 px-3 py-1 rounded text-sm'}, 'Delete')
                                                                                                                                                                                                               )
                                                                                                                                                                             )
                                                                                                                                             ))
                                                                                     )
                                                         )
                               );
}

ReactDOM.createRoot(document.getElementById('root')).render(React.createElement(TaskManager));
