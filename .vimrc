syntax on

let &colorcolumn=join(range(81,9999),",") 

"set showtabline=2
"set laststatus=2
set number
set relativenumber
set nowrap
set background=dark
set cursorline

nnoremap <C-t> :tabnew<cr>
":noremap <leader>u :w<Home>silent <End> !urlview<CR>
":noremap ,, :w<Home>silent <End> !urlview<CR>

hi Visual cterm=NONE ctermfg=0 ctermbg=4
hi Comment cterm=NONE ctermfg=4 ctermbg=NONE
hi MatchParen cterm=NONE ctermfg=1 ctermbg=NONE
hi LineNr ctermfg=6
hi cursorline cterm=NONE ctermfg=15 ctermbg=0
hi colorcolumn ctermbg=NONE ctermfg=1

"hi Constant cterm=NONE ctermfg=0 ctermbg=4 
"hi Special  cterm=NONE ctermfg=3 ctermbg=NONE
"hi Function cterm=NONE ctermfg=0 ctermbg=1

if has("autocmd")
  au VimEnter,InsertLeave * silent execute '!echo -ne "\e[2 q"' | redraw!
  au InsertEnter,InsertChange *
\ if v:insertmode == 'i' | 
\   silent execute '!echo -ne "\e[6 q"' | redraw! |
\ elseif v:insertmode == 'r' |
\   silent execute '!echo -ne "\e[4 q"' | redraw! |
\ endif
au VimLeave * silent execute '!echo -ne "\e[ q"' | redraw!
endif


