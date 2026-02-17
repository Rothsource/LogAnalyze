import matplotlib.pyplot as plt

def create_pie_chart(summary_data, output_filename="ip_comparison.png"):
    
    if not summary_data:
        print("No data to create chart")
        return
    
    num_ips = len(summary_data)
    cols = 3 
    rows = (num_ips + cols - 1) // cols
    
    fig, axes = plt.subplots(rows, cols, figsize=(15, 5 * rows))
    axes = axes.flatten() if num_ips > 1 else [axes]
    
    for idx, (ip, data) in enumerate(summary_data.items()):
        total   = data['total']
        success = data['success']
        failed  = data['failed']
        other   = total - success - failed
        
        labels  = []
        sizes   = []
        colors  = []
        
        if success > 0:
            labels.append(f'Success ({success})')
            sizes.append(success)
            colors.append('#2ecc71')
        
        if failed > 0:
            labels.append(f'Failed ({failed})')
            sizes.append(failed)
            colors.append('#e74c3c')
        
        if other > 0:
            labels.append(f'Other ({other})')
            sizes.append(other)
            colors.append('#95a5a6')
        
        axes[idx].pie(sizes, labels=labels, colors=colors, autopct='%1.1f%%', startangle=90)
        axes[idx].set_title(f'{ip}\n(Total: {total})', fontsize=12, weight='bold')
    
    for idx in range(num_ips, len(axes)):
        axes[idx].axis('off')
    
    plt.tight_layout()
    plt.savefig(output_filename, dpi=300, bbox_inches='tight')
    print(f"Comparison chart saved: {output_filename}")
    plt.show()
    
def create_bruteforce_chart(bruteforce_data, output_filename="bruteforce_likelihood.png"):
    
    if not bruteforce_data:
        print(" No data to create brute force chart")
        return
    
    num_ips = len(bruteforce_data)
    cols = 3
    rows = (num_ips + cols - 1) // cols
    
    fig, axes = plt.subplots(rows, cols, figsize=(15, 5 * rows))
    axes = axes.flatten() if num_ips > 1 else [axes]
    
    threat_colors = {
        'CRITICAL'   : '#e74c3c',  
        'SUSPICIOUS' : '#f39c12',  
        'NORMAL'     : '#2ecc71'   
    }
    
    for idx, (ip, data) in enumerate(bruteforce_data.items()):
        threat_level = data.get('threat_level', 'UNKNOWN')
        likelihood   = float(data.get('likelihood', 0))
        safe_pct     = 100 - likelihood
        
        labels = [f'Threat\n{likelihood:.1f}%', f'Safe\n{safe_pct:.1f}%']
        sizes  = [likelihood, safe_pct]
        colors = [threat_colors.get(threat_level, '#95a5a6'), '#95a5a6']
        
        axes[idx].pie(sizes, labels=labels, colors=colors, autopct='%1.1f%%', startangle=90)
        axes[idx].set_title(f'{ip}\n{threat_level}', 
                           fontsize=12, 
                           weight='bold',
                           color=threat_colors.get(threat_level, '#000000'))
    
    for idx in range(num_ips, len(axes)):
        axes[idx].axis('off')
    
    plt.tight_layout()
    plt.savefig(output_filename, dpi=300, bbox_inches='tight')
    print(f"Brute force chart saved: {output_filename}")
    plt.show()