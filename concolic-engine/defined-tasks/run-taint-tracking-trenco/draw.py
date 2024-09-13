import json
import numpy as np
import matplotlib.pyplot as plt

def load_data(json_file_path):
    """Load the data from a JSON file."""
    with open(json_file_path, 'r') as file:
        data = json.load(file)
    return data

def filter_data(data):
    """Filter out data items where the first value in the sublist is smaller than 10."""
    filtered_data = [item for item in data if item[0] >= 10]
    return filtered_data

def generate_cdf(data, label):
    """Generate the CDF data for plotting."""
    sorted_data = np.sort(data)
    cdf = np.arange(1, len(sorted_data) + 1) / float(len(sorted_data)) * 100  # Convert CDF to percentage

    return sorted_data, cdf, label

def find_first_significant_point(sorted_data, cdf, threshold=0.1):
    """Find the first point where the CDF exceeds a given threshold."""
    for x, y in zip(sorted_data, cdf):
        if y > threshold:
            return x, y
    return sorted_data[0], cdf[0]  # Fallback in case no point exceeds the threshold


def main():
    # Path to your JSON file
    json_file_path = 'analysis.time.json'
    
    # Load the data
    data = load_data(json_file_path)
    
    # Filter the data to remove items where the first value is smaller than 10
    filtered_data = filter_data(data)
    
    # Separate the vectors
    first_vector = np.array([item[0] for item in filtered_data])
    # Cap the values at 30 seconds in second_vector
    second_vector = np.array([item[1] * 0.02 for item in filtered_data])
    third_vector = np.array([item[2] for item in filtered_data])

    num_zeros = np.sum(third_vector == 0)
    print(f"Number of zeros in third vector: {num_zeros}")
    print(f"Percentage of zeros in third vector: {num_zeros / len(third_vector) * 100}%")
    
    # Combine all data for the "in total" CDF
    combined_data = first_vector + second_vector + third_vector

    # Generate CDF data for each vector
    first_sorted, first_cdf, first_label = generate_cdf(first_vector, 'Gadget Detection Phase')
    second_sorted, second_cdf, second_label = generate_cdf(second_vector, 'Exploit Generation Phase')
    third_sorted, third_cdf, third_label = generate_cdf(third_vector, 'Gadget Verification Phase')
    combined_sorted, combined_cdf, combined_label = generate_cdf(combined_data, 'All Phases')
    
    # Find intersection points
    first_intersection = find_first_significant_point(first_sorted, first_cdf)
    second_intersection = find_first_significant_point(second_sorted, second_cdf)
    third_intersection = find_first_significant_point(third_sorted, third_cdf)
    combined_intersection = find_first_significant_point(combined_sorted, combined_cdf)
    
    # Print intersection points
    # print(f"First Vector Intersection: X = {first_intersection[0]}, Y = {first_intersection[1]}")
    # print(f"Second Vector Intersection: X = {second_intersection[0]}, Y = {second_intersection[1]}")
    print(f"Third Vector Intersection: X = {third_intersection[0]}, Y = {third_intersection[1]}")
    print(f"Combined Data Intersection: X = {combined_intersection[0]}, Y = {combined_intersection[1]}")

    # Plotting all CDFs on the same graph with different lines
    plt.figure(figsize=(8, 6))
    plt.plot(first_sorted, first_cdf, linestyle=':', label=first_label, )
    plt.plot(second_sorted, second_cdf, linestyle='--', label=second_label)
    plt.plot(third_sorted, third_cdf, linestyle='-.', label=third_label)
    plt.plot(combined_sorted, combined_cdf, linestyle='-', label=combined_label)

    # Set the x-axis to a logarithmic scale
    plt.xscale('log', base=2)  # Set the base of the log scale to 2
    
    # Set the x-axis limits to stop exactly at 2^16
    powers_of_2 = [2**i for i in range(0, 17)]  # Range from 0 to 16 to include 2^0 to 2^16
    tick_labels = [f'$2^{{{i}}}$' for i in range(0, 17)]  # Correctly format labels as 2^0, 2^1, 2^2, ... 2^16

    plt.xticks(powers_of_2, tick_labels)  # Show labels as 2^0, 2^1, 2^2, ...
    plt.xlim(min(powers_of_2), max(powers_of_2))

    # Set the y-axis from 0 to 100 to represent the percentage
    plt.ylim(0, 100)

    plt.tick_params(axis='both', which='major', labelsize=12)

    # Labeling
    plt.xlabel('Analysis Time (seconds)', fontdict={'fontsize': 16})
    plt.ylabel('Percentage of Websites (%)', fontdict={'fontsize': 16})
    plt.grid(True, which="both", ls="--")
    plt.legend()

    # Save the figure

    plt.savefig('cdf_analysis_time_all_vectors_filtered_logx_specific.png', dpi=600)
    plt.show()

if __name__ == "__main__":
    main()
